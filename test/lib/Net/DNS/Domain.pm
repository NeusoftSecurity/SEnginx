package Net::DNS::Domain;

#
# $Id: Domain.pm 1161 2014-01-13 15:48:07Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1161 $)[1];


=head1 NAME

Net::DNS::Domain - Domain Name System domains

=head1 SYNOPSIS

    use Net::DNS::Domain;

    $domain = new Net::DNS::Domain('example.com');
    $name   = $domain->name;

=head1 DESCRIPTION

The Net::DNS::Domain module implements a class of abstract DNS
domain objects with associated class and instance methods.

Each domain object instance represents a single DNS domain which
has a fixed identity throughout its lifetime.

Internally, the primary representation is a (possibly empty) list
of ASCII domain name labels, and optional link to an arbitrary
origin domain object topologically closer to the DNS root.

The computational expense of Unicode character-set conversion is
partially mitigated by use of caches.

=cut


use strict;
use integer;
use Carp;


use constant ASCII => eval {
	require Encode;
	Encode::find_encoding('ASCII');				# return encoding object
} || 0;

use constant UTF8 => eval {
	die if Encode::decode_utf8( chr(91) ) ne '[';		# not UTF-EBCDIC  [see UTR#16 3.6]
	Encode::find_encoding('UTF8');				# return encoding object
} || 0;

use constant LIBIDN => eval {
	require Net::LibIDN;					# tested and working
	UTF8 && Net::LibIDN::idn_to_ascii( pack( 'U*', 20013, 22269 ), 'utf-8' ) eq 'xn--fiqs8s';
} || 0;


=head1 METHODS

=head2 new

    $object = new Net::DNS::Domain('example.com');

Creates a domain object which represents the DNS domain specified
by the character string argument. The argument consists of a
sequence of labels delimited by dots.

A character preceded by \ represents itself, without any special
interpretation.

Arbitrary 8-bit codes can be represented by \ followed by exactly
three decimal digits.
Character code points are ASCII, irrespective of the character
coding scheme employed by the underlying platform.

Argument string literals should be delimited by single quotes to
avoid escape sequences being interpreted as octal character codes
by the Perl compiler.

The character string presentation format follows the conventions
for zone files described in RFC1035.

=cut

use vars qw($ORIGIN);

my $cache1 = {};
my $cache2 = {};
my $expire;

sub new {
	my ( $class, $s ) = @_;
	croak 'domain identifier undefined' unless defined $s;

	my $k = join '', $s, $class, $ORIGIN || '';		# cache key
	my $cache = $$cache1{$k} ||= $$cache2{$k};		# two layer cache
	return $cache if defined $cache;

	( $cache1, $cache2, $expire ) = ( {}, $cache1, 500 ) unless $expire--;	  # recycle cache

	my $self = bless {}, $class;

	$s =~ s/\\\\/\\092/g;					# disguise escaped escape
	$s =~ s/\\\./\\046/g;					# disguise escaped dot

	my $label = $self->{label} = $s eq '@' ? [] : [split /\056/, _encode_ascii($s)];

	foreach my $l (@$label) {
		$l = _unescape($l) if $l =~ /\\/;
		( substr( $l, 63 ) = '', carp 'domain label truncated' )
				if ( length($l) || croak 'empty domain label' ) > 63;
	}

	$$cache1{$k} = $self;					# cache object reference

	return $self if $s =~ /\.$/;				# fully qualified name
	$self->{origin} = $ORIGIN || return $self;		# dynamically scoped $ORIGIN
	return $self;
}


=head2 name

    $name = $domain->name;

Returns the domain name as a character string corresponding to the
"common interpretation" to which RFC1034, 3.1, paragraph 9 alludes.

Character escape sequences are used to represent a dot inside a
domain name label and the escape character itself.

Any non-printable code point is represented using the appropriate
numerical escape sequence.

=cut

my $dot = _decode_ascii( pack 'C', 46 );

sub name {
	my $self = shift;

	return $self->{name} if defined $self->{name};

	my $lref = $self->{label} || [];
	my $head = _decode_ascii( join chr(46), map _escape($_), @$lref );
	my $tail = $self->{origin} || return $self->{name} = $head || $dot;
	return $self->{name} = $tail->name unless length $head;
	return $self->{name} = join $dot, $head, $tail->name;
}


=head2 fqdn

    @fqdn = $domain->fqdn;

Returns a character string containing the fully qualified domain
name, including the trailing dot.

=cut

sub fqdn {
	my $name = &name;
	return $name =~ /[$dot]$/o ? $name : $name . $dot;	# append trailing dot
}


=head2 xname

    $xname = $domain->xname;

Interprets an extended name containing Unicode domain name labels
encoded as Punycode A-labels.

Domain names containing Unicode characters are supported if the
Net::LibIDN module is installed.

=cut

sub xname {
	return &name unless LIBIDN;

	my $name = &name;
	return $name unless $name =~ /xn--/;

	my $self = shift;
	return $self->{xname} ||= UTF8->decode( Net::LibIDN::idn_to_unicode( $name, 'utf-8' ) || $name );
}


=head2 label

    @label = $domain->label;

Identifies the domain by means of a list of domain labels.

=cut

sub label {
	my $self = shift;

	my @head = map _decode_ascii( _escape($_) ), @{$self->{label}};
	my $tail = $self->{origin} || return (@head);
	return ( @head, $tail->label );
}


=head2 string

    $string = $object->string;

Returns a character string containing the fully qualified domain
name as it appears in a zone file.

Characters which are recognised by RFC1035 zone file syntax are
represented by the appropriate escape sequence.

=cut

sub string {
	( my $name = &name ) =~ s/(['"\$;@])/\\$1/;		# escape special char
	return $name =~ /[$dot]$/o ? $name : $name . $dot;	# append trailing dot
}


=head2 origin

    $create = origin Net::DNS::Domain( $ORIGIN );
    $result = &$create( sub{ new Net::DNS::RR( 'mx MX 10 a' ); } );
    $expect = new Net::DNS::RR( "mx.$ORIGIN. MX 10 a.$ORIGIN." );

Class method which returns a reference to a subroutine wrapper
which executes a given constructor in a dynamically scoped context
where relative names become descendents of the specified $ORIGIN.

=cut

my $placebo = sub { my $constructor = shift; &$constructor; };

sub origin {
	my $class = shift;
	my $name = shift || return $placebo;

	my $domain = new Net::DNS::Domain($name);
	return sub {						# closure w.r.t. $domain
		my $constructor = shift;
		local $ORIGIN = $domain;			# dynamically scoped $ORIGIN
		&$constructor;
			}
}


########################################

use vars qw($AUTOLOAD);

sub AUTOLOAD {				## Default method
	no strict;
	@_ = ("method $AUTOLOAD undefined");
	goto &{'Carp::confess'};
}


sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)


sub _decode_ascii {			## translate ASCII to perl string
	my $s = shift;

	my $t = substr $s, 0, 0;				# pre-5.18 taint workaround
	my $z = length $t;
	return pack "x$z a*", ASCII->decode($s) if ASCII;

	# partial transliteration for non-ASCII character encodings
	$s =~ tr
	[\040-\176\000-\377]
	[ !"#$%&'()*+,-./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~?] unless ASCII;

	return $s;						# native 8-bit code
}


sub _encode_ascii {			## translate perl string to ASCII
	my $s = shift;

	my $t = substr $s, 0, 0;				# pre-5.18 taint workaround
	my $z = length $t;
	return pack "x$z a*", Net::LibIDN::idn_to_ascii( $s, 'utf-8' ) || croak 'invalid name'
			if LIBIDN && $s =~ /[^\000-\177]/;

	return pack "x$z a*", ASCII->encode($s) if ASCII;

	# partial transliteration for non-ASCII character encodings
	$s =~ tr
	[ !"#$%&'()*+,-./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~\000-\377]
	[\040-\176\077] unless ASCII;

	return $s;						# ASCII
}


my %esc = eval {			## precalculated ASCII escape table
	my %table;

	foreach ( 33 .. 126 ) {					# ASCII printable
		$table{pack( 'C', $_ )} = pack 'C', $_;
	}

	# minimal character escapes
	foreach ( 46, 92 ) {					# \. \\
		$table{pack( 'C', $_ )} = pack 'C*', 92, $_;
	}

	foreach ( 0 .. 32, 127 .. 255 ) {			# \ddd
		$table{pack( 'C', $_ )} = sprintf '\\%03u', $_;
	}

	return %table;
};


sub _escape {				## Insert escape sequences in string
	my $s = shift;
	$s =~ s/([^\055\101-\132\141-\172\060-\071])/$esc{$1}/eg;
	return $s;
}


my %unesc = eval {			## precalculated numeric escape table
	my %table;

	foreach ( 0 .. 255 ) {
		$table{_encode_ascii sprintf( '%03u', $_ )} = pack 'C', $_;
	}

	$table{_encode_ascii('092')} = pack 'C*', 92, 92;	# escaped escape

	return %table;
};


sub _unescape {				## Remove escape sequences in string
	my $s = shift;
	$s =~ s/\134([\060-\071]{3})/$unesc{$1}/eg;		# numeric escape
	$s =~ s/\134(.)/$1/g;					# character escape
	return $s;
}


1;
__END__


########################################

=head1 BUGS

Coding strategy is intended to avoid creating unnecessary argument
lists and stack frames. This improves efficiency at the expense of
code readability.

Platform specific character coding features are conditionally
compiled into the code.


=head1 COPYRIGHT

Copyright (c)2009-2011 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::LibIDN>, L<Net::DNS>, RFC1034, RFC1035, RFC5891,
Unicode Technical Report #16

=cut

