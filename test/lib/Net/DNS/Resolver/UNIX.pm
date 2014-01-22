package Net::DNS::Resolver::UNIX;
use base Net::DNS::Resolver::Base;

#
# $Id: UNIX.pm 1096 2012-12-28 13:35:15Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1096 $)[1]; # Unchanged since 1021

=head1 NAME

Net::DNS::Resolver::UNIX - UNIX Resolver Class

=cut


use strict;


my $resolv_conf = "/etc/resolv.conf";
my $dotfile	= '.resolv.conf';

my @config_path;
push( @config_path, $ENV{HOME} ) if exists $ENV{HOME};
push( @config_path, '.' );


sub init {
	my ($class) = @_;

	$class->read_config_file($resolv_conf) if -f $resolv_conf && -r _;

	foreach my $dir (@config_path) {
		my $file = "$dir/$dotfile";
		$class->read_config_file($file) if -f $file && -r _ && -o _;
	}

	$class->read_env;

	my $defaults = $class->defaults;

	if ( !$defaults->{domain} && @{$defaults->{searchlist}} ) {
		$defaults->{domain} = $defaults->{searchlist}[0];
	} elsif ( !@{$defaults->{searchlist}} && $defaults->{domain} ) {
		$defaults->{searchlist} = [$defaults->{domain}];
	}
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS::Resolver;

=head1 DESCRIPTION

This class implements the OS specific portions of C<Net::DNS::Resolver>.

No user serviceable parts inside, see L<Net::DNS::Resolver|Net::DNS::Resolver>
for all your resolving needs.

=head1 COPYRIGHT

Copyright (c) 1997-2002 Michael Fuhr.

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Resolver>

=cut
