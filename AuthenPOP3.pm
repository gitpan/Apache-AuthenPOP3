package Apache::AuthenPOP3;

$Apache::AuthenPOP3::VERSION = '0.01';

# $Id: AuthenPOP3.pm,v 1.7 2002/10/23 19:35:11 reggers Exp $

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use Net::POP3;

use strict;

sub handler {
    my $r = shift;

    # Continue only if the first request.

    return OK unless $r->is_initial_req;

    # Grab the password, or return if HTTP_UNAUTHORIZED

    my ($res, $pass) = $r->get_basic_auth_pw;
    return $res if $res;

    # Get the user name, but reject if none supplied

    my $user = $r->connection->user;
    if ($user eq '') {
	    $r->log_reason("Apache::AuthenPOP3 (no user)", $r->uri);
	    $r->note_basic_auth_failure;
	    return AUTH_REQUIRED;
	}

    # get host from Apache configuration; default to me.

    my $host = $r->dir_config("Auth_POP3_host") || "localhost";

    # connect to POP3 server and authenticate

    my $pop= Net::POP3->new($host);
    if (!defined($pop)) {
	$r->log_reason("Apache::AuthenPOP3 (conn) $host", $r->uri);
	return SERVER_ERROR;
    }

    my $stat= $pop->login($user,$pass); $pop->quit();

    # Check login status and return accordingly.

    if (!defined($stat)) {
        $r->log_reason("Apache::AuthenPOP3 (auth) FAIL", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    return OK;
}

1;

__END__

=head1 NAME

Apache::AuthenPOP3 - Authentication via an POP3 server

=head1 SYNOPSIS

 # Configuration in httpd.conf

 PerlModule Apache::AuthenPOP3

 # Authentication in .htaccess

 AuthName POP3 User Authentication
 AuthType Basic

 # authenticate via POP3
 PerlAuthenHandler Apache::AuthenPOP3

 # PerlSetVar Auth_POP3_host localhost
 PerlSetVar Auth_POP3_host do.ma.in

 require user fred

The AuthType is limited to Basic.

=head1 DESCRIPTION

This module allows authentication against servers that implement
the POP3 authentication protocol (simple gateways that don't implement
all of the POP3 protocol will suffice).

AuthenPOP3 relies on the Net::POP3 module to do the real work.

=head1 LIST OF TOKENS

=over 4

=item *
Auth_POP3_host

The POP3 server host: either its name or its dotted quad IP number.
This parameter defaults to "localhost" -- the loopback interface to
the same system.

=back

=head1 BEWARE

The POP3 protocol is very simple -- passwords are passed in the clear and
may be snooped on insecure networks. Using the POP3 service on the localhost
is secure as there is no network data to be snooped.

=head1 AUTHORS

This module B<Apache::AuthenPOP3> by Reg Quinton
E<lt>reggers@ist.uwaterloo.caE<gt> using strategy of AuthenIMAP by Malcolm
Beattie.

=head1 COPYRIGHT

The Apache::AuthenPOP3 module is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut
