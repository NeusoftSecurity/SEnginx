package Net::DNS::RR::A;

#
# $Id: A.pm 1096 2012-12-28 13:35:15Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1096 $)[1]; # Unchanged since 1043

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::A - DNS A resource record

=cut


use strict;
use integer;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	$self->{address} = unpack "\@$offset a4", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{address} && length $self->{address};
	return pack 'a4', $self->{address};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{address} && length $self->{address};
	return $self->address;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->address(shift);
}


sub address {
	my $self = shift;

	return join '.', unpack( 'C4', $self->{address} ) unless @_;

	# Note: pack masks overlarge values, mostly without warning
	my @part = split /\./, shift || '';
	my $last = pop(@part) || 0;
	$self->{address} = pack 'C4', @part, (0) x ( 3 - @part ), $last;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN A address');

    $rr = new Net::DNS::RR(
	name	=> 'example.com',
	type	=> 'A',
	address => '192.0.2.1'
	);

=head1 DESCRIPTION

Class for DNS Address (A) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 address

    $IPv4_address = $rr->address;
    $rr->address( $IPv4_address );

Version 4 IP address represented using dotted-quad notation.


=head1 COPYRIGHT

Copyright (c)1997-1998 Michael Fuhr. 

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.4.1

=cut
