# Copyright 2024 The Persephone Authors
# Licensed under the Apache License, Version 2.0

package SyTest::HomeserverFactory::Persephone;

use strict;
use warnings;
use 5.014;

use Carp;

use base qw( SyTest::HomeserverFactory );

require SyTest::Homeserver::Persephone;

sub _init {
    my $self = shift;
    my ($args) = @_;

    $args->{bindir} //= "/usr/local/bin";
    $self->{args}{bindir} = delete $args->{bindir};
    $self->{args}{print_output} = delete $args->{print_output} // 0;

    $self->SUPER::_init($args);
}

sub get_options {
    my $self = shift;

    return (
        "d|persephone-binary-directory=s" => \$self->{args}{bindir},
        "S|server-log+" => \$self->{args}{print_output},

        $self->SUPER::get_options(),
    );
}

sub print_usage {
    print STDERR <<EOF
   -d, --persephone-binary-directory
                     - Path to the directory containing the Persephone binary
                       (default: /usr/local/bin)

   -S, --server-log  - Enable server logging output (can be repeated for more verbosity)

EOF
}

sub create_server {
    my $self = shift;
    my %params = @_;

    return SyTest::Homeserver::Persephone->new(
        %params,
        %{ $self->{args} },
    );
}

1;
