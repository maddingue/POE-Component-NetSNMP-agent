#!/usr/bin/perl
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'POE::Component::NetSNMP::agent',
    license             => 'perl',
    dist_author         => 'Sebastien Aperghis-Tramoni <sebastien@aperghis.net>',
    dist_version_from   => 'lib/POE/Component/NetSNMP/agent.pm',
    requires => {
        'NetSNMP::agent'    => 5.0000,
        'POE'               => 0.3502,
        'SNMP'              => 5.0000,
    },
    build_requires => {
        'Test::More'        => 0,
    },
    add_to_cleanup      => [ 'POE-Component-NetSNMP-agent-*' ],
);

$builder->create_build_script();
