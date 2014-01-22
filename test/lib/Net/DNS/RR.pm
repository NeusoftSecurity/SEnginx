package Net::DNS::RR;

#
# $Id: RR.pm 1158 2014-01-10 22:30:40Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1158 $)[1];


=head1 NAME

Net::DNS::RR - DNS Resource Record base class

=head1 SYNOPSIS

    use Net::DNS;

    $rr = new Net::DNS::RR('example.com IN A 192.0.2.99');

    $rr = new Net::DNS::RR(
	    name    => 'example.com',
	    type    => 'A',
	    address => '192.0.2.99'
	    );


=head1 DESCRIPTION

Net::DNS::RR is the base class for DNS Resource Record (RR) objects.
See also the manual pages for each specific RR type.

=cut


use constant COMPATIBLE => 1;		## enable architecture transition code

use strict;
use integer;
use Carp;

use Net::DNS::Parameters;
use Net::DNS::DomainName;


=head1 METHODS

B<WARNING!!!>  Do not assume the RR objects you receive from a query
are of a particular type -- you must always check the object type
before calling any of its methods.  If you call an unknown method,
you will get an error message and execution will be terminated.

=cut

sub new {
	return &_new_from_rdata if COMPATIBLE && ref $_[1];	# resolve new() usage conflict

	return eval { scalar @_ > 2 ? &_new_hash : &_new_string; } || do {
		my $error = $@	  || 'eval{} aborted without setting $@, contrary to Perl specification' . "\n";
		my $class = shift || __PACKAGE__;
		my @parse = split /\s+/, shift || '';
		croak join ' ', "${error}in new $class(", substr( "@parse @_", 0, 50 ), '... )';
			}
}


=head2 new (from string)

    $a	   = new Net::DNS::RR('host.example.com. 86400 A 192.0.2.1');
    $mx	   = new Net::DNS::RR('example.com. 7200 MX 10 mailhost.example.com.');
    $cname = new Net::DNS::RR('www.example.com 300 IN CNAME host.example.com');
    $txt   = new Net::DNS::RR('txt.example.com 3600 HS TXT "text data"');

Returns an RR object of the appropriate type, or a C<Net::DNS::RR>
object if the type is not implemented.	The attribute values are
extracted from the string passed by the user.  The syntax of the
argument string follows the RFC1035 specification for zone files,
and is compatible with the result returned by the string method.

The name and RR type are required; all other information is optional.
If omitted, the TTL defaults to 0 and the RR class defaults to IN.
Omitting the optional fields is useful for creating the empty RDATA
sections required for certain dynamic update operations.  See the
C<Net::DNS::Update> manual page for additional examples.

All names are interpreted as fully qualified domain names.
The trailing dot (.) is optional.

=cut

my $PARSE_REGEX = q/("[^"]*"|'[^']*')|;[^\n]*|\s|\)$/;

sub _new_string {
	my $base;
	local $_;
	( $base, $_ ) = @_;
	croak 'argument absent or undefined' unless defined $_;

	# parse into quoted strings, contiguous non-whitespace and (discarded) comments
	s/\\\\/\\092/g;						# disguise escaped escape
	s/\\"/\\034/g;						# disguise escaped double quote
	s/\\'/\\039/g;						# disguise escaped single quote
	s/\\;/\\059/g;						# disguise escaped semicolon
	s/\n(\S)/$1/g if COMPATIBLE;				# gloss over syntax errors in Net::DNS::SEC test data
	my @parse = grep defined && length, split /$PARSE_REGEX/o;
	my ( $name, @token ) = grep !/^[()]$/, @parse;		# discard brackets

	my ( $t1, $t2, $t3 ) = @token;
	croak 'unable to parse RR string' unless defined $t1;

	my ( $ttl, $class );
	unless ( defined $t2 ) {
		$token[0] = 'ANY' unless $typebyname{$t1};	# <name> <type>
	} elsif ( defined $t3 && $classbyname{$t2} ) {
		$ttl   = shift @token;				# <name> <ttl> <class> <type>
		$class = shift @token;
	} elsif ( $t1 =~ /^\d/ ) {
		$ttl = shift @token;				# <name> <ttl> [<class>] <type>
		$class = shift @token if $t2 =~ /^CLASS\d/;
	} elsif ( $classbyname{$t1} || $t1 =~ /^CLASS\d/ ) {
		$class = shift @token;				# <name> <class> [<ttl>] <type>
		$ttl = shift @token if $t2 =~ /^\d/;
	}

	my $type      = shift(@token);
	my $populated = scalar @token;

	my $self = $base->_subclass( $type, $populated );	# create RR object
	$self->name($name);
	$self->ttl($ttl) if defined $ttl;			# undefined TTL meaningful in zone file
	$self->class($class) if defined $class;

	return $self unless $populated;				# empty RR

	if ( $token[0] =~ /#$/ ) {
		shift @token;					# RFC3597 hexadecimal format
		my $count = shift(@token) || 0;
		my $rdata = pack 'H*', join '', @token;
		my $rdlen = $self->{rdlength} = length $rdata;
		croak 'length and hexadecimal data inconsistent' unless $rdlen == $count;
		return $self unless $count;
		return ref($self)->new( $self, \$rdata, 0 ) if COMPATIBLE;
		$self->decode_rdata( \$rdata, 0 );		# unpack RDATA
		return $self;
	} elsif ( COMPATIBLE && $self->{OLD} ) {
		$self->{ttl} ||= 0;
		return ref($self)->new_from_string( $self, join( ' ', @token ), \@token );
	}

	$self->parse_rdata(@token);				# parse arguments
	return $self;
}


=head2 new (from hash)

    $rr = new Net::DNS::RR(
	    name    => 'host.example.com',
	    ttl	    => 86400,
	    class   => 'IN',
	    type    => 'A',
	    address => '192.0.2.1'
	    );
 
    $rr = new Net::DNS::RR(
	    name    => 'txt.example.com',
	    type    => 'TXT',
	    txtdata => [ 'one', 'two' ]
	    );

Returns an RR object of the appropriate type, or a C<Net::DNS::RR>
object if the type is not implemented.	See the manual pages for
each RR type to see what fields the type requires.

The C<name> and C<type> fields are required; all others are optional.
If omitted, C<ttl> defaults to 0 and C<class> defaults to IN.
Omitting the optional fields is useful for creating the empty RDATA
sections required for certain dynamic update operations.

=cut

sub _new_hash {
	my ( $base, %argument ) = @_;

	my %attribute = ( name => '.' );
	while ( my ( $key, $value ) = each %argument ) {
		$attribute{lc $key} = $value;
	}

	my ( $name, $type, $class, $ttl ) = @attribute{qw(name type class ttl)};
	delete @attribute{qw(name class type ttl rdlength)};	# strip non-RDATA fields

	my $populated = scalar %attribute;			# RDATA specified

	my $self = $base->_subclass( $type, $populated );	# RR with defaults (if appropriate)
	$self->name($name);
	$self->class($class) if defined $class;			# specify CLASS
	$self->ttl($ttl)     if defined $ttl;			# specify TTL

	while ( my ( $attribute, $value ) = each %attribute ) {
		if ( UNIVERSAL::isa( $value, 'ARRAY' ) ) {
			$self->$attribute(@$value);		# attribute => [ ... ]
		} else {
			$self->$attribute($value);		# attribute => value
		}
	}

	if ( COMPATIBLE && $self->{OLD} ) {
		$self->{ttl} ||= 0;
		$self->_normalize_dnames if $populated;		# strip trailing dot from RDATA names
	}

	return $self;
}


=head2 decode

    ( $rr, $next ) = decode Net::DNS::RR( \$data, $offset, @opaque );

Decodes a DNS resource record at the specified location within a
DNS packet.

The argument list consists of a reference to the buffer containing
the packet data and offset indicating where resource record begins.
Remaining arguments, if any, are passed as opaque data to
subordinate decoders.

Returns a C<Net::DNS::RR> object and the offset of the next record
in the packet.

An exception is raised if the data buffer contains insufficient or
corrupt data.

Any remaining arguments are passed as opaque data to subordinate
decoders and do not form part of the published interface.

=cut

use constant RRFIXEDSZ => length pack 'n2 N n', (0) x 4;

sub decode {
	my $base = shift;
	my ( $data, $offset, @opaque ) = @_;

	my ( $owner, $fixed ) = decode Net::DNS::DomainName1035(@_);

	my $index = $fixed + RRFIXEDSZ;
	die 'corrupt wire-format data' if length $$data < $index;
	my $type = unpack "\@$fixed n", $$data;
	my $self = $base->_subclass( typebyval($type) );
	$self->{owner} = $owner;
	@{$self}{qw(class ttl rdlength)} = unpack "\@$fixed x2 n N n", $$data;
	$self->class( classbyval( $self->{class} ) ) if COMPATIBLE;

	my $next = $index + $self->{rdlength};
	die 'corrupt wire-format data' if length $$data < $next;

	if (COMPATIBLE) {
		ref($self)->new( $self, $data, $index, @opaque );
		return wantarray ? ( $self, $next ) : $self;
	}

	$self->decode_rdata( $data, $index, @opaque ) if $next > $index or $self->type eq 'OPT';

	return wantarray ? ( $self, $next ) : $self;
}


=head2 encode

    $data = $rr->encode( $offset, @opaque );

Returns the C<Net::DNS::RR> in binary format suitable for inclusion
in a DNS packet buffer.

The offset indicates the intended location within the packet data
where the C<Net::DNS::RR> is to be stored.

Any remaining arguments are opaque data which are passed intact to
subordinate encoders.

=cut

sub encode {
	my $self = shift;
	my ( $offset, @opaque ) = @_;
	( $offset, @opaque ) = ( 0x4000, {} ) unless scalar @_;

	if (COMPATIBLE) {
		my ( $hash, $packet ) = @opaque;
		$packet ||= bless {}, q(Net::DNS::Packet);
		$packet->{compnames} = $hash || {};
		my $name   = $self->name;
		my $owner  = $self->{owner}->encode(@_);
		my $index  = $offset + length($owner) + RRFIXEDSZ;
		my $rdata  = eval { $self->rr_rdata( $packet, $index, @opaque ); } || '';
		my $itype  = typebyname( $self->type );
		my $iclass = classbyname( $self->class );
		delete $packet->{compnames};
		return pack 'a* n2 N n a*', $owner, $itype, $iclass, $self->ttl, length $rdata, $rdata;
	}

	my $owner = $self->{owner}->encode(@_);
	my $type  = $self->{type};
	my $class = $self->{class} || 1;
	my $index = $offset + length($owner) + RRFIXEDSZ;
	my $rdata = eval { $self->encode_rdata( $index, @opaque ); } || '';
	return pack 'a* n2 N n a*', $owner, $type, $class, $self->ttl, length $rdata, $rdata;
}


=head2 canonical

    $data = $rr->canonical;

Returns the C<Net::DNS::RR> in canonical binary format suitable for
DNSSEC signature validation.

The absence of the associative array argument signals to subordinate
encoders that the canonical uncompressed lower case form of embedded
domain names is to be used.

=cut

sub canonical {
	my $self = shift;

	if (COMPATIBLE) {
		my $dummy  = $self->name;
		my $owner  = $self->{owner}->canonical;
		my $index  = RRFIXEDSZ + length $owner;
		my $rdata  = eval { $self->_canonicalRdata($index); } || '';
		my $itype  = typebyname( $self->type );
		my $iclass = classbyname( $self->class );
		return pack 'a* n2 N n a*', $owner, $itype, $iclass, $self->ttl, length $rdata, $rdata;
	}

	my $owner = $self->{owner}->canonical;
	my $type  = $self->{type};
	my $class = $self->{class} || 1;
	my $index = RRFIXEDSZ + length $owner;
	my $rdata = eval { $self->encode_rdata($index); } || '';
	pack 'a* n2 N n a*', $owner, $type, $class, $self->ttl, length $rdata, $rdata;
}


=head2 name

    $name = $rr->name;

Returns the owner name of the record.

=cut

sub name {
	my $self = shift;

	if (COMPATIBLE) {
		@{$self}{qw(name owner)} = ( undef, new Net::DNS::DomainName1035(shift) ) if @_;
		$self->{owner} = new Net::DNS::DomainName1035( $self->{name} ) unless $self->{owner};
		return $self->{name} = $self->{owner}->name;
	}

	$self->{owner} = new Net::DNS::DomainName1035(shift) if scalar @_;
	$self->{owner}->name if defined wantarray;
}


=head2 type

    $type = $rr->type;

Returns the record type.

=cut

sub type {
	my $self = shift;

	croak 'not possible to change RR->type' if scalar @_;

	return $self->{type} || 'A' if COMPATIBLE;
	typebyval( $self->{type} || 1 );
}


=head2 class

    $class = $rr->class;

Resource record class.

=cut

sub class {
	my $self = shift;

	if (COMPATIBLE) {
		$self->{class} = classbyval( classbyname(shift) ) if @_;
		return $self->{class} || 'IN';
	}

	$self->{class} = classbyname(shift) if scalar @_;
	classbyval( $self->{class} || 1 ) if defined wantarray;
}


=head2 ttl

    $ttl = $rr->ttl;
    $ttl = $rr->ttl(3600);

Resource record time to live in seconds.

=cut

# The following time units are recognised, but are not part of the
# published API.  These are required for parsing BIND zone files but
# should not be used in other contexts.
my %unit = ( W => 604800, D => 86400, H => 3600, M => 60, S => 1 );
%unit = ( %unit, map { /\D/ ? lc($_) : $_ } %unit );

sub ttl {
	my $self = shift;

	return $self->{ttl} || 0 unless scalar @_;		# avoid defining rr->{ttl}

	my $ttl = 0;
	my %time = reverse split /(\D)\D*/, shift() . 'S';
	while ( my ( $u, $t ) = each %time ) {
		$ttl += $t * ( $unit{$u} || croak qq(bad time: $t$u) );
	}
	$self->{ttl} = $ttl;
}


=head2 rdata

    $rr = new Net::DNS::RR( type => NULL, rdata => 'arbitrary' );

Resource record data section when viewed as opaque octets.

=cut

sub rdata {
	my $self = shift;

	return eval { $self->encode_rdata( 0x4000, {} ); } unless scalar @_;

	my $rdata = $self->{rdata}    = shift;
	my $rdlen = $self->{rdlength} = length $rdata;
	my $hash  = {};
	$self->decode_rdata( \$rdata, 0, $hash ) if $rdlen;
	croak 'compression pointer seen in rdata' if keys %$hash;
}


=head2 print

    $rr->print;

Prints the record to the standard output.  Calls the B<string>
method to get the RR string representation.

=cut

sub print {
	print shift->string, "\n";
}


=head2 string

    print $rr->string, "\n";

Returns a string representation of the RR using the zone file format
described in RFC1035.  All domain names are fully qualified with
trailing dot.  This differs from RR attribute methods, which omit
the trailing dot.

=cut

sub string {
	my $self = shift;

	my $name = $self->name if COMPATIBLE;
	my @core = ( $self->{owner}->string, $self->ttl, $self->class, $self->type );

	my $rdata = $self->rdstring;

	return join "\t", @core, '; no data' unless length $rdata;

	chomp $rdata;
	$rdata =~ s/\n+/\n\t/g;
	return join "\t", @core, $rdata;
}


=head2 rdstring

    $rdstring = $rr->rdstring;

Returns a string representation of the RR-specific data.

=cut

sub rdstring {
	my $self = shift;

	my $rdata = eval {
		return $self->rdatastr if COMPATIBLE;
		return $self->format_rdata;
	} || '';
	carp $@ if $@;

	return $rdata;
}


=head2 plain

    $plain = $rr->plain;

Returns a simplified single line representation of the RR using the
zone file format defined in RFC1035.  This facilitates interaction
with programs like nsupdate which have simplified RR parsers.

=cut

sub plain {
	join ' ', shift->token;
}


=head2 token

    @token = $rr->token;

Returns a token list representation of the RR zone file string.

=cut

sub token {
	my $self = shift;

	my @core = ( $self->{owner}->string, $self->ttl, $self->class, $self->type );
	local $_ = $self->rdstring;
	s/\\\\/\\092/g;						# disguise escaped escape
	s/\\"/\\034/g;						# disguise escaped double quote
	s/\\'/\\039/g;						# disguise escaped single quote
	s/\\;/\\059/g;						# disguise escaped semicolon
	my @parse = grep defined && length, split /$PARSE_REGEX/o;
	my @token = @core, grep !/^[()]$/, @parse;		# discard brackets
}


###################################################################################

=head1 Sorting of RR arrays

Sorting of RR arrays is done by Net::DNS::rrsort(), see documentation
for L<Net::DNS>. This package provides class methods to set the
sorting functions used for a particular RR based on its attributes.


=head2 set_rrsort_func

    Net::DNS::RR::SRV->set_rrsort_func(
	'priority',
	sub {
	    my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
	    $a->priority <=> $b->priority
	    || $b->weight <=> $a->weight;
	    }
	);

    Net::DNS::RR::SRV->set_rrsort_func(
	'default_sort',
	sub {
	    my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
	    $a->priority <=> $b->priority
	    || $b->weight <=> $a->weight;
	    }
	);

set_rrsort_func needs to be called as a class method. The first
argument is the attribute name on which the sorting will need to take
place. If you specify "default_sort" then that is the sort algorithm
that will be used in the case that rrsort() is called without an RR
attribute as argument.

The second argument is a reference to a comparison function that uses
the global variables $a and $b in the C<from Net::DNS>(!!)package.
During sorting, the variables $a and $b will contain references to
objects of the class from which you called the set_prop_sort. In other
words, you can rest assured that the above sorting function will only
be applied to Net::DNS::RR::SRV objects.

The above example is the sorting function implemented in SRV.

=cut

use vars qw(%rrsortfunct);

sub set_rrsort_func {
	my $class     = shift;
	my $attribute = shift;
	my $funct     = shift;

	#    print "Using ".__PACKAGE__."set_rrsort: $class\n";
	my ($type) = $class =~ m/^.*::(.*)$/;
	$Net::DNS::RR::rrsortfunct{$type}{$attribute} = $funct;
}

sub get_rrsort_func {
	my $class     = shift;
	my $attribute = shift;					# can be undefined.
	my $sortsub;
	my ($type) = $class =~ m/^.*::(.*)$/;

	if (	   defined($attribute)
		&& exists( $Net::DNS::RR::rrsortfunct{$type} )
		&& exists( $Net::DNS::RR::rrsortfunct{$type}{$attribute} ) ) {

		#  The default overwritten by the class variable in Net::DNS
		return $Net::DNS::RR::rrsortfunct{$type}{$attribute};
	} elsif ( !defined($attribute)
		&& exists( $Net::DNS::RR::rrsortfunct{$type} )
		&& exists( $Net::DNS::RR::rrsortfunct{$type}{default_sort} ) ) {

		#  The default overwritten by the class variable in Net::DNS
		return $Net::DNS::RR::rrsortfunct{$type}{default_sort};
	} elsif ( defined($attribute) ) {

		return sub {
			my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
			exists( $a->{$attribute} )
					? $a->$attribute() <=> $b->$attribute()
					: $a->canonical() cmp $b->canonical();
		};
	} else {
		return sub {
			my ( $a, $b ) = ( $Net::DNS::a, $Net::DNS::b );
			$a->canonical() cmp $b->canonical();
		};
	}

	return $sortsub;
}


###################################################################################
##
##	Default implementation for unknown RR type
##
###################################################################################

sub decode_rdata {			## decode rdata from wire-format octet string
	my ( $self, $data, $offset ) = @_;
	my $rdlength = $self->{rdlength} || length $$data;
	$self->{rdata} = substr $$data, $offset, $rdlength;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;
	$self->{rdata} || '';
}


sub format_rdata {			## format rdata portion of RR string
	my $self = shift;
	my $data = $self->{rdata} || $self->encode_rdata;	# unknown RR, per RFC3597
	my $size = length $data;
	join ' ', '\\#', $size, $size ? unpack( 'H*', $data ) : ();
}


sub parse_rdata {			## parse RR attributes in argument list
	my $self = shift;
	return unless shift;
	die join ' ', $self->type, 'not implemented' if ref($self) eq __PACKAGE__;
	die join ' ', 'zone file representation not defined for', $self->type;
}


sub defaults { }			## set attribute default values


sub dump {				## print internal data structure
	require Data::Dumper;
	$Data::Dumper::Sortkeys = sub { return [sort keys %{$_[0]}] };
	return Data::Dumper::Dumper(shift) if defined wantarray;
	print Data::Dumper::Dumper(shift);
}


#
#  Net::DNS::RR->_subclass($rrtype)
#  Net::DNS::RR->_subclass($rrtype, $default)
#
# Create a new object blessed into appropriate RR subclass, after
# loading the subclass module (if necessary).  A subclass with no
# corresponding module will be regarded as unknown and blessed
# into the RR base class.
#
# The optional second argument indicates that default values are
# to be copied into the newly created object.

use vars qw(%_LOADED %_MINIMAL %_DEFAULT);

sub _subclass {
	my $class   = shift;
	my $rrtype  = shift || '';
	my $default = shift;

	my $subclass = $_LOADED{$rrtype};			# load once only
	unless ($subclass) {
		die "Usage:\t\$rr = new Net::DNS::RR( name $rrtype ... )\n"
				unless $class eq __PACKAGE__;
		my $number = typebyname($rrtype);
		my $mnemon = typebyval($number);
		my $module = join '::', $class, $mnemon;
		$module =~ s/[^A-Za-z0-9:]//g;			# expect the unexpected
		$subclass = eval("require $module") ? $module : $class;
		$subclass = $module if $mnemon eq 'OPT';	# default to OPT declared below
		my $object = bless {type => $number}, $subclass;
		if (COMPATIBLE) {
			no strict;
			my %stash = %{"${subclass}::"};		# symbol table hash
			$object->{OLD}++ unless exists $stash{encode_rdata};
			$object->{type} = $mnemon;
		}
		$_MINIMAL{$subclass} = [%$object];		# cache minimal content
		$object->defaults if $subclass eq $module;
		$_DEFAULT{$subclass} = [%$object];		# cache default content
		$_LOADED{$rrtype}    = $subclass;
	}

	my $prebuilt = $default ? $_DEFAULT{$subclass} : $_MINIMAL{$subclass};
	return bless {@$prebuilt}, $subclass;			# create object
}


###################################################################################
##	Compatibility interface to allow old and new RR architectures to coexist
##
##	"new" modules inherit these methods to wrap themselves in "old" clothing.
###################################################################################

sub _new_from_rdata {			## decode rdata from wire-format byte string
	my $class = shift;
	my $self  = shift;
	$self->decode_rdata(@_) if $self->{rdlength} or $self->type eq 'OPT';
	return $self;
}


sub new_from_string {			## parse RR attributes in argument list
	my ( $class, $self, undef, $parse ) = @_;		# new_from_string() is a misnomer
	confess 'new_from_string() deprecated' unless ref($self);
	$self->parse_rdata(@$parse);				# string already parsed in _new_string()
	return $self;
}


sub rdatastr {				## format rdata portion of RR string
	return shift->format_rdata;
}


sub rr_rdata {				## encode rdata as wire-format byte string
	my $self   = shift;
	my $packet = shift;
	return $self->encode_rdata(@_);
}


sub _canonicaldata {			## encode RR in canonical form
	&canonical;
}

sub _canonicalRdata {			## encode rdata in canonical form
	my ( $self, $offset ) = @_;
	return $self->rr_rdata( undef, $offset || 0 );
}


sub _name2wire {			## emulate
	my $class = shift;
	new Net::DNS::DomainName(shift)->encode();
}

sub _normalize_ownername { }

sub _normalize_dnames { }


###################################################################################

use vars qw($AUTOLOAD);

sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)

sub AUTOLOAD {				## Default method
	my $self = shift;
	confess "method '$AUTOLOAD' undefined" unless ref $self;

	my $method = $1 if $AUTOLOAD =~ m/^.*::(.*)$/;

	if (COMPATIBLE) {
		return $self->{$method} = shift if @_;
		return $self->{$method} if exists $self->{$method};
	}

	my $object = $self->string;

	@_ = (<<"END");
***  FATAL PROGRAM ERROR!!	Unknown method '$method'
***  which the program has attempted to call for the object:
***
***  $object
***
***  This object does not have a method '$method'.  THIS IS A BUG
***  IN THE CALLING SOFTWARE, which incorrectly assumes that the
***  object would be of a particular type.  The type of an object
***  should be checked before calling any of its methods.
END
	no strict;
	goto &{'Carp::confess'};
}


###################################################################################

## Stub implementation of Net::DNS::RR::OPT to avoid a barrage of confusing failure
## reports if the subtype implementation module is absent or fails to load.

package Net::DNS::RR::OPT;

sub AUTOLOAD {				## stub out all OPT attributes
	my @a0;				## delivering 0, '' or () according to context
	return @a0 if wantarray;
	$! = scalar @a0;
}


1;
__END__


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr. 

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2005-2007 Olaf Kolkman.

Portions Copyright (c)2007,2012 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Question>,
L<Net::DNS::Packet>, L<Net::DNS::Update>,
RFC1035 Section 4.1.3, RFC1123, RFC3597

=cut

