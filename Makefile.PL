#!/usr/bin/perl
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'POE::Component::NetSNMP::agent',
    LICENSE             => 'perl',
    AUTHOR              => 'Sebastien Aperghis-Tramoni <sebastien@aperghis.net>',
    VERSION_FROM        => 'lib/POE/Component/NetSNMP/agent.pm',
    ABSTRACT_FROM       => 'lib/POE/Component/NetSNMP/agent.pm',
    PREREQ_PM => {
        # prereqs
        'NetSNMP::agent'    => 0,
        'POE'               => 0,
        'SNMP'              => 0,

        # build/test prereqs
        'Test::More'        => 0,
    },
    PL_FILES            => {},
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'POE-Component-NetSNMP-agent-*' },
);
