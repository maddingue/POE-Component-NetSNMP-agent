package POE::Component::NetSNMP::agent;

use 5.006;
use strict;
use warnings;

use Carp;
use POE;


our $VERSION = "0.100";


#
# spawn()
# -----
sub spawn {
    my $class = shift;
    croak "error: odd number of arguments" unless @_ % 2 == 0;

    my %defaults = (
        AgentName   => "perl",
        AgentX      => 0,
    );

    my %args = ( %defaults, @_ );

    # check for mandatory arguments
    croak "error: no OID defined"       unless $args{AgentOID};
    croak "error: no callback defined"  unless $args{Callback};
    croak "error: callback must be either a POE event name or a coderef"
        if ref $args{Callback} and ref $args{Callback} ne "CODE";
    carp "warning: callback '$args{Callback}' doesn't look like a POE event"
        if !ref $args{Callback} and $args{Callback} !~ /^\w+$/;


    POE::Session->create(
        heap => {
            args    => \%args,
        },

        inline_states => {
            _start => sub {
                $_[KERNEL]->yield("init");
                $_[KERNEL]->alias_set( $_[HEAP]{args}{Alias} )
                    if $_[HEAP]{args}{Alias};
            },

            _stop => sub {
                $_[HEAP]->{agent}->shutdown;
            },

            init => sub {
                my ($kernel, $heap) = @_[ KERNEL, HEAP ];
                my $args = $heap->{args};
                my %opts;
                $opts{Name}   = $args->{AgentName};
                $opts{AgentX} = $args->{AgentX};
                $opts{Ports}  = $args->{AgentPorts} if defined $args->{AgentPorts};

                # create the NetSNMP sub-agent
                $heap->{agent} = NetSNMP::agent->new(%opts);

                # register the sub-agent
                $kernel->yield("register") if ref $args->{Callback};
            },

            register => sub {
                my ($kernel, $heap, $sender) = @_[ KERNEL, HEAP, SENDER ];
                my $args = $heap->{args};

                my $poe_wrapper;

                if (ref $args->{Callback}) {
                    # simpler & faster callback mechanism
                    my @poe_params = @_[ 0 .. ARG0-1 ];
                    $poe_wrapper = sub {
                        @_ = ( @poe_params, [], [@_] );
                        goto $args->{Callback}
                    };
                }
                else {
                    # standard POE callback mechanism
                    $poe_wrapper = $sender->callback($args->{Callback});
                }

                # create & register the NetSNMP sub-agent
                my $r = $heap->{agent}->register(
                    $args->{AgentName}, $args->{AgentOID}, $poe_wrapper);

                if (not $r) {
                    $kernel->post($sender, $args->{Errback}, "register")
                        if $args->{Errback};
                    return
                }

                # find the sockets used to communicate with AgentX master..
                my ($timeout, @fds) = SNMP::select_info();

                # ... and let POE kernel handle them
                for my $fd (@fds) {
                    open my $fh, "+<&=", $fd;
                    $kernel->select_read($fh, "agent_check");
                }
            },

            agent_check => sub {
                # process the incoming data and invoque the callback
                $_[HEAP]{agent}->agent_check_and_process(0);
            },
        },
    );
}


__PACKAGE__

__END__

=head1 NAME

POE::Component::NetSNMP::agent - AgentX clients with NetSNMP::agent and POE


=head1 VERSION

Version 0.100


=head1 SYNOPSIS




=head1 DESCRIPTION

This module is a thin wrapper around C<NetSNMP::agent> to use it within
a C<POE>-based program.


=head1 METHODS

=head2 spawn

B<Options>

=over

=item *

C<AgentName>

=item *

C<AgentOID>

=item *

C<AgentPorts>

=item *

C<AgentX>

=item *

C<Callback>

=item *

C<Errback>

=back


=head1 POE EVENTS

=head2 register

B<Arguments:>

=over

=item ARG0: event name for handling the SNMP requests

=back


=head1 SEE ALSO

L<POE>

L<NetSNMP::agent>, L<NetSNMP::ASN>, L<NetSNMP::OID>

Net-SNMP web site: L<http://www.net-snmp.org/>


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc POE::Component::NetSNMP::agent

You can also look for information at:

=over

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/Public/Dist/Display.html?Name=POE-Component-NetSNMP-agent>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/POE-Component-NetSNMP-agent>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/POE-Component-NetSNMP-agent>

=item * Search CPAN

L<http://search.cpan.org/dist/POE-Component-NetSNMP-agent/>

=back


=head1 BUGS

Please report any bugs or feature requests to
C<bug-poe-component-netsnmp-agent at rt.cpan.org>,
or through the web interface at
L<https://rt.cpan.org/Public/Dist/Display.html?Name=POE-Component-NetSNMP-agent>.
I will be notified, and then you'll automatically be notified of
progress on your bug as I make changes.


=head1 ACKNOWLEDGEMENTS

Thanks to Rocco Caputo and Rob Bloodgood for their help on C<#poe>.


=head1 AUTHOR

SE<eacute>bastien Aperghis-Tramoni C<< <sebastien at aperghis.net> >>


=head1 LICENSE AND COPYRIGHT

Copyright 2011 SE<eacute>bastien Aperghis-Tramoni.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See L<http://dev.perl.org/licenses/> for more information.

=cut

