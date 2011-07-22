package POE::Component::NetSNMP::agent;

use 5.006;
use strict;
use warnings;

use parent qw< POE::Session >;

use Carp;
use List::MoreUtils qw< after >;
use NetSNMP::agent;
use POE;
use SNMP ();
use version ();


our $VERSION = "0.300";


use constant {
    TYPE            => 0,
    VALUE           => 1,

    HAVE_SORT_KEY_OID
                    => eval "use Sort::Key::OID 0.04 'oidsort'; 1" ? 1 : 0,

    BUGGY_NETSNMP_AGENT => eval {
        version->new($NetSNMP::agent::VERSION) < version->new("5.04")
    },
};


#
# spawn()
# -----
sub spawn {
    my $class = shift;
    croak "error: odd number of arguments" unless @_ % 2 == 0;

    my %defaults = (
        Name    => "perl",
        AgentX  => 0,
        Ping    => 10,
    );

    my %args = ( %defaults, @_ );

    my @poe_opts;
    push @poe_opts, options => { trace => 1, debug => 1, default => 1 }
        if $args{Debug};

    # check arguments
    carp "warning: errback '$args{Errback}' doesn't look like a POE event"
        if $args{Errback} and $args{Errback} !~ /^\w+$/;

    # create the POE session
    my $session = $class->create(
        heap => {
            args        => \%args,
            oid_tree    => {},
            ping_delay  => $args{Ping},
        },

        inline_states => {
            _start      => \&ev_start,
            _stop       => \&ev_stop,
            init        => \&ev_init,
            register    => \&ev_register,
            agent_check => \&ev_agent_check,

            tree_handler    => \&ev_tree_handler,
            add_oid_entry   => \&ev_add_oid_entry,
            add_oid_tree    => \&ev_add_oid_tree,
        },

        @poe_opts,
    );

    return $session
}


# ==============================================================================
# POE events
#


#
# ev_start()
# --------
sub ev_start {
    $_[KERNEL]->yield("init");
    $_[KERNEL]->alias_set( $_[HEAP]{args}{Alias} )
        if $_[HEAP]{args}{Alias};
}


#
# ev_stop()
# -------
sub ev_stop {
    $_[HEAP]{agent}->shutdown;
}


#
# ev_init()
# -------
sub ev_init {
    my $args = $_[HEAP]{args};
    my %opts;
    $opts{Name}   = $args->{Name};
    $opts{AgentX} = $args->{AgentX};
    $opts{Ports}  = $args->{Ports} if defined $args->{Ports};

    # create the NetSNMP sub-agent
    $_[HEAP]{agent} = NetSNMP::agent->new(%opts);

    # if auto-handle is requested, register our own OID tree handler
    $_[KERNEL]->yield(register => $args->{AutoHandle}, "tree_handler")
        if $args->{AutoHandle};
}


#
# ev_register()
# -----------
sub ev_register {
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

    # manually call agent_check_and_process() once so it opens
    # the sockets to AgentX master
    $kernel->delay(agent_check => 0, "register");
}


#
# ev_agent_check()
# --------------
sub ev_agent_check {
    my ($kernel, $heap, $case) = @_[ KERNEL, HEAP, ARG0 ];

    $case ||= "";

    # schedule next check
    $kernel->delay(agent_check => $heap->{ping_delay}),

    # process the incoming data and invoque the callback
    SNMP::_check_timeout();
    $heap->{agent}->agent_check_and_process(0);

    if ($case eq "register") {
        # find the sockets used to communicate with AgentX master..
        my ($block, $to_sec, $to_usec, @fd_set)
            = SNMP::_get_select_info();

        # ... and let POE kernel handle them
        for my $fd (@fd_set) {
            # create a file handle from the given file descriptor
            open my $fh, "+<&=", $fd;

            # first unregister the given file handles from
            # POE::Kernel, in case some were already registered,
            # then register them, with this event as callback
            $kernel->select_read($fh);
            $kernel->select_read($fh, "agent_check");
        }
    }
}


#
# ev_tree_handler()
# ---------------
sub ev_tree_handler {
    my ($kernel, $heap, $args) = @_[ KERNEL, HEAP, ARG1 ];
    my ($handler, $reg_info, $request_info, $requests) = @$args;
    my $oid_tree = $heap->{oid_tree};
    my $oid_list = $heap->{oid_list};

    # the rest of the code works like a classic NetSNMP::agent callback
    my $mode = $request_info->getMode;

    for (my $request = $requests; $request; $request = $request->next) {
        my $oid = $request->getOID->as_oid;

        if ($mode == MODE_GET) {
            if (exists $oid_tree->{$oid}) {
                my $type  = $oid_tree->{$oid}[TYPE];
                my $value = $oid_tree->{$oid}[VALUE];
                $value = "$value" if BUGGY_NETSNMP_AGENT;
                $request->setValue($type, $value);
            }
            else {
                $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
                next
            }
        }
        elsif ($mode == MODE_GETNEXT) {
            # find the OID after the requested one
            my ($next_oid) = after { $_ eq $oid } @$oid_list;
            $next_oid ||= "";
            $next_oid ||= @$oid_list[0] unless exists $oid_tree->{$oid};

            if (exists $oid_tree->{$next_oid}) {
                my $type  = $oid_tree->{$next_oid}[TYPE];
                my $value = $oid_tree->{$next_oid}[VALUE];
                $value = "$value" if BUGGY_NETSNMP_AGENT;
                $request->setOID($next_oid);
                $request->setValue($type, $value);
            }
            else {
                $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
                next
            }
        }
        else {
            $request->setError($request_info, SNMP_ERR_GENERR);
            next
        }
    }
}


#
# ev_add_oid_entry()
# ----------------
sub ev_add_oid_entry {
    my ($kernel, $heap, $oid, $type, $value)
        = @_[ KERNEL, HEAP, ARG0, ARG1, ARG2 ];

    my $oid_tree = $heap->{oid_tree};

    # make sure that the OID start with a dot
    $oid = ".$oid" unless index($oid, ".") == 0;

    # add the given entry to the tree
    $oid_tree->{$oid} = [ $type, $value ];

    # calculate the sorted list of OID entries
    @{ $heap->{oid_list} } = HAVE_SORT_KEY_OID ?
        oidsort(keys %$oid_tree) : sort by_oid keys %$oid_tree;
}


#
# ev_add_oid_tree()
# ---------------
sub ev_add_oid_tree {
    my ($kernel, $heap, $new_tree) = @_[ KERNEL, HEAP, ARG0 ];

    my $oid_tree = $heap->{oid_tree};

    # make sure that the OIDs start with a dot
    my @oids = map { ".$_" unless index($_, ".") == 0 } keys %$new_tree;

    # add the given entries to the tree
    @{$oid_tree}{@oids} = values %$new_tree;

    # calculate the sorted list of OID entries
    @{ $heap->{oid_list} } = HAVE_SORT_KEY_OID ?
        oidsort(keys %$oid_tree) : sort by_oid keys %$oid_tree;
}


# ==============================================================================
# Methods
#


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


#
# add_oid_entry()
# -------------
sub add_oid_entry {
    my ($self, $oid, $type, $value) = @_;

    # check arguments
    croak "error: no OID defined"       unless $oid;
    croak "error: no type defined"      unless $type;
    croak "error: no value defined"     unless $value;

    # register the given OID and callback
    POE::Kernel->post($self, add_oid_entry => $oid, $type, $value);

    return $self
}


#
# add_oid_tree()
# ------------
sub add_oid_tree {
    my ($self, $new_tree) = @_;

    # check arguments
    croak "error: expected a hashref"   unless ref $new_tree eq "HASH";

    # register the given OID and callback
    POE::Kernel->post($self, add_oid_tree => $new_tree);

    return $self
}


# ==============================================================================
# Functions
#


#
# by_oid()
# ------
# sort() sub-function, for sorting by OID
#
sub by_oid ($$) {
    my (undef, @a) = split /\./, $_[0];
    my (undef, @b) = split /\./, $_[1];
    my $v = 0;
    $v ||= $a[$_] <=> $b[$_] for 0 .. $#a;
    return $v
}


# ==============================================================================
# Hackery
#

{   # live-patch NetSNMP::OID
    package NetSNMP::OID;
    sub as_oid { return join ".", "", $_[0]->to_array }
}


__PACKAGE__

__END__

=head1 NAME

POE::Component::NetSNMP::agent - AgentX clients with NetSNMP::agent and POE


=head1 VERSION

Version 0.200


=head1 SYNOPSIS

Like a traditional C<NetSNMP::agent>, made POE aware:

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

Even simpler, let the module do all the stupid work:

    use NetSNMP::ASN;
    use POE qw< Component::NetSNMP::agent >;


    POE::Session->create(
        inline_states => {
            _start => sub {
                $_[HEAP]{agent} = POE::Component::NetSNMP::agent->spawn(
                    Alias       => "snmp_agent",
                    AgentX      => 1,
                    AutoHandle  => "1.3.6.1.4.1.32272",
                );

                $_[KERNEL]->yield("update_tree");
            },
            update_tree => \&update_tree,
        },
    );

    POE::Kernel->run;
    exit;

    sub update_tree {
        my ($kernel, $heap) = @_[ KERNEL, HEAP ];

        # populate the OID tree at regular intervals with
        # add_oid_entry and add_oid_tree
    }

See also in F<eg/> for more ready-to-use examples.


=head1 DESCRIPTION

This module is a thin wrapper around C<NetSNMP::agent> to use it within
a POE-based program, its basic use being the same as you would do
without POE: C<register> one or more OIDs with their associated callbacks,
then within a callback process & answer the requests with C<setValue()>,
C<setOID()>, C<setError()>, etc.

C<POE::Component::NetSNMP::agent> also provides a simpler mechanism,
similar to C<SNMP::Extension::PassPersist>, if you just want to handle
C<get> and C<getnext> requests over an OID tree: set the C<Autohandle>
option to the a OID, then add OID entries with C<add_oid_entry> or
C<add_oid_tree>.

The module will try to automatically recover from a lost connection with
AgentX master (see the C<Ping> option), but you can force a check by
C<post>ing to C<agent_check>;

Note that most of the API is available both as POE events and as object
methods, in an attempt to make it a bit easier for people not fully used
to POE.

This module can use C<Sort::Key::OID> when it is available, for sorting
OIDs faster than with the internal pure Perl function.


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

B<Component options>

=over

=item *

C<Alias> - I<(optional)> sets the session alias

=item *

C<AutoHandle> - I<(optional)> sets the component to auto-handle C<get>
and C<getnext> request to the given OID

=item *

C<Debug> - I<(optional)> when true, enables debug mode on this session

=item *

C<Ping> - I<(optional)> sets the ping delay between manual agent checks
in seconds; default is 10 seconds

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


=head2 add_oid_entry

Add an OID entry to be auto-handled by the agent.

B<Arguments:>

=over

=item 1. I<(mandatory)> OID

=item 2. I<(mandatory)> ASN type; use the constants given by
C<NetSNMP::ASN> like C<ASN_COUNTER>, C<ASN_GAUGE>, C<ASN_OCTET_STR>..

=item 3. I<(mandatory)> value

=back

B<Example:>

    $agent->add_oid_entry("1.3.6.1.4.1.32272.1", ASN_OCTET_STR, "oh hai");

    $agent->add_oid_entry("1.3.6.1.4.1.32272.2", ASN_OCTET_STR,
        "i can haz oh-eye-deez??");


=head2 add_oid_tree

Add multiple OID entries to be auto-handled by the agent.

B<Arguments:>

=over

=item 1. I<(mandatory)> OID tree; must be a hashref with the following
structure:

    {
        OID => [ ASN_TYPE, VALUE ],
        ...
    }

=back

B<Example:>

    %oid_tree = (
        "1.3.6.1.4.1.32272.1" => [ ASN_OCTET_STR, "oh hai" ];
        "1.3.6.1.4.1.32272.2" => [ ASN_OCTET_STR, "i can haz oh-eye-deez??" ];
    );

    $agent->add_oid_tree(\%oid_tree);



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


=head2 add_oid_entry

Add an OID entry to be auto-handled by the agent.

B<Arguments:>

=over

=item ARG0: I<(mandatory)> OID

=item ARG1: I<(mandatory)> ASN type; use the constants given by
C<NetSNMP::ASN> like C<ASN_COUNTER>, C<ASN_GAUGE>, C<ASN_OCTET_STR>..

=item ARG2: I<(mandatory)> value

=back

B<Example:>

    POE::Kernel->post($agent, add_oid_entry =>
        "1.3.6.1.4.1.32272.1", ASN_OCTET_STR, "oh hai");

    POE::Kernel->post($agent, add_oid_entry =>
        "1.3.6.1.4.1.32272.2", ASN_OCTET_STR, "i can haz oh-eye-deez??");


=head2 add_oid_tree

Add multiple OID entries to be auto-handled by the agent.

B<Arguments:>

=over

=item ARG0: I<(mandatory)> OID tree; must be a hashref with the following
structure:

    {
        OID => [ ASN_TYPE, VALUE ],
        ...
    }

=back

B<Example:>

    %oid_tree = (
        "1.3.6.1.4.1.32272.1" => [ ASN_OCTET_STR, "oh hai" ];
        "1.3.6.1.4.1.32272.2" => [ ASN_OCTET_STR, "i can haz oh-eye-deez??" ];
    );

    POE::Kernel->post($agent, add_oid_tree => \%oid_tree);



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

