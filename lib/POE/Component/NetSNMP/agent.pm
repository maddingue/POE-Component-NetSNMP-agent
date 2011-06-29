package POE::Component::NetSNMP::agent;

use 5.006;
use strict;
use warnings;

use parent qw< POE::Session >;

use Carp;
use NetSNMP::agent ();
use POE;
use SNMP ();


our $VERSION = "0.100";


#
# spawn()
# -----
sub spawn {
    my $class = shift;
    croak "error: odd number of arguments" unless @_ % 2 == 0;

    my %defaults = (
        Name    => "perl",
        AgentX  => 0,
    );

    my %args = ( %defaults, @_ );

    # check arguments
    carp "warning: errback '$args{Errback}' doesn't look like a POE event"
        if $args{Errback} and $args{Errback} !~ /^\w+$/;

    # create the POE session
    my $session = $class->create(
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
                $_[HEAP]{agent}->shutdown;
            },

            init => sub {
                my $args = $_[HEAP]{args};
                my %opts;
                $opts{Name}   = $args->{Name};
                $opts{AgentX} = $args->{AgentX};
                $opts{Ports}  = $args->{Ports} if defined $args->{Ports};

                # create the NetSNMP sub-agent
                $_[HEAP]{agent} = NetSNMP::agent->new(%opts);

                # find the sockets used to communicate with AgentX master..
                my ($timeout, @fds) = SNMP::select_info();

                # ... and let POE kernel handle them
                for my $fd (@fds) {
                    open my $fh, "+<&=", $fd;
                    $_[KERNEL]->select_read($fh, "agent_check");
                }
            },

            register => sub {
                my ($kernel, $heap, $sender, $oid, $callback)
                    = @_[ KERNEL, HEAP, SENDER, ARG0, ARG1 ];
                my $args = $heap->{args};

                my $poe_wrapper;

                if (ref $callback) {
                    # simpler & faster callback mechanism
                    my @poe_params = @_[ 0 .. ARG0-1 ];
                    $poe_wrapper = sub {
                        @_ = ( @poe_params, [], [@_] );
                        goto $callback
                    };
                }
                else {
                    # standard POE callback mechanism
                    $poe_wrapper = $sender->callback($callback);
                }

                # create & register the NetSNMP sub-agent
                my $r = $heap->{agent}->register(
                    $args->{Name}, $oid, $poe_wrapper);

                if (not $r) {
                    $kernel->post($sender, $args->{Errback}, "register")
                        if $args->{Errback};
                    return
                }
            },

            agent_check => sub {
                # process the incoming data and invoque the callback
                $_[HEAP]{agent}->agent_check_and_process(0);
            },
        },
    );

    return $session
}


#
# register()
# --------
sub register {
    my ($self, $oid, $callback) = @_;

    # check arguments
    croak "error: no OID defined"       unless $oid;
    croak "error: no callback defined"  unless $callback;
    croak "error: callback must be a coderef"
        unless ref $callback and ref $callback eq "CODE";

    # register the given OID and callback
    POE::Kernel->post($self, register => $oid, $callback);

    return $self
}


__PACKAGE__

__END__

=head1 NAME

POE::Component::NetSNMP::agent - AgentX clients with NetSNMP::agent and POE


=head1 VERSION

Version 0.100


=head1 SYNOPSIS

    use NetSNMP::agent;
    use POE qw< Component::NetSNMP::agent >;


    my $agent = POE::Component::NetSNMP::agent->spawn(
        Alias   => "snmp_agent",
        AgentX  => 1,
    );

    $agent->register("1.3.6.1.4.1.32272", \&agent_handler);

    POE::Kernel->run;
    exit;

    sub agent_handler {
        my ($kernel, $heap, $args) = @_[ KERNEL, HEAP, ARG1 ];
        my ($handler, $reg_info, $request_info, $requests) = @$args;

        # the rest of the code works like a classic NetSNMP::agent callback
        my $mode = $request_info->getMode;

        for (my $request = $requests; $request; $request = $request->next) {
            if ($mode == MODE_GET) {
                # ...
            }
            elsif ($mode == MODE_GETNEXT) {
                # ...
            }
            else {
                # ...
            }
        }
    }

See also in F<eg/> for more ready-to-use examples.


=head1 DESCRIPTION

This module is a thin wrapper around C<NetSNMP::agent> to use it within
a C<POE>-based program. Its usage is mostly the same:

=over

=item *

C<spwan> a session object

=item *

C<register> one or more OIDs with associated callbacks (either via the
object method or via the POE event, as you see fit)

=back


=head1 METHODS

=head2 spawn

Create and return a POE session for handling NetSNMP requests.

B<NetSNMP::agent options>

=over

=item *

C<Name> - I<(optional)> sets the agent name, defaulting to C<"perl">.
The underlying library will try to read a F<$name.conf> Net-SNMP
configuration file.

=item *

C<AgentX> - I<(optional)> be a sub-agent (0 = false, 1 = true).
The Net-SNMP master agent must be running first.

=item *

C<Ports> - I<(optional)> sets the ports this agent will listen
on (e.g.: C<"udp:161,tcp:161">).

=back

B<POE options>

=over

=item *

C<Alias> - I<(optional)> sets the session alias

=item *

C<Errback> - I<(optional)> sets the error callback.

=back

B<Example:>

    my $agent = POE::Component::NetSNMP::agent->spawn(
        Alias   => "snmp_agent",
        AgentX  => 1,
    );


=head2 register

Register a callback handler for a given OID.

B<Arguments:>

=over

=item 1. I<(mandatory)> OID to register

=item 2. I<(mandatory)> request handler callback; must be a coderef

=back

B<Example:>

    $agent->register("1.3.6.1.4.1.32272.1", \&tree_1_handler);
    $agent->register("1.3.6.1.4.1.32272.2", \&tree_2_handler);


=head1 POE EVENTS

=head2 register

Register a callback handler for a given OID.

B<Arguments:>

=over

=item ARG0: I<(mandatory)> OID to register

=item ARG1: I<(mandatory)> request handler callback; must be an event
name or a coderef

=back

B<Example:>

    POE::Kernel->post($agent, register => "1.3.6.1.4.1.32272.1", "tree_1_handler");
    POE::Kernel->post($agent, register => "1.3.6.1.4.1.32272.2", "tree_2_handler");


=head1 SEE ALSO

L<POE>, L<http://poe.perl.org/>

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

