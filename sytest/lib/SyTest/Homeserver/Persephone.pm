# Copyright 2024 The Persephone Authors
# Licensed under the Apache License, Version 2.0

package SyTest::Homeserver::Persephone;

use strict;
use warnings;
use 5.014;

use base qw( SyTest::Homeserver SyTest::Homeserver::ProcessManager );

use Carp;
use File::Basename qw( dirname );
use File::Path qw( make_path remove_tree );
use POSIX qw( strftime );

sub _init {
    my $self = shift;
    my ($args) = @_;

    $self->{$_} = delete $args->{$_} for qw( bindir print_output );

    $self->{bindir} //= "/usr/local/bin";
    $self->{print_output} //= 0;

    # Allocate ports for this homeserver instance
    $self->{ports} = {
        client     => main::alloc_port("persephone_client"),
        federation => main::alloc_port("persephone_federation"),
    };

    $self->SUPER::_init($args);
}

sub configure {
    my $self = shift;
    my %params = @_;

    $self->{print_output} = $params{print_output} // $self->{print_output};

    $self->SUPER::configure(%params);
}

# Generate YAML config for Persephone
sub _get_config {
    my $self = shift;

    my $hs_dir = $self->{hs_dir};
    my $bind_host = $self->{bind_host};
    my $client_port = $self->{ports}{client};
    my $fed_port = $self->{ports}{federation};

    # Use a unique database name based on port to avoid conflicts
    my $db_name = "persephone_sytest_$client_port";

    # Drogon requires IP addresses, not hostnames like "localhost"
    my $bind_ip = ($bind_host eq 'localhost') ? '127.0.0.1' : $bind_host;

    return <<"YAML";
database:
  host: "localhost"
  port: 5432
  database_name: "$db_name"
  user: "postgres"
  password: ""

matrix:
  server_name: "$bind_host:$fed_port"
  server_key_location: "$hs_dir/server_key.key"

webserver:
  ssl: false
  port: $client_port
  federation_port: $fed_port
  bind_host: "$bind_ip"

log_level: "debug"
YAML
}

sub start {
    my $self = shift;

    my $hs_dir = $self->{hs_dir};
    my $output = $self->{output};

    # Ensure the directory exists
    -d $hs_dir or make_path($hs_dir);

    # Write config file
    my $config = $self->_get_config();
    my $config_path = "$hs_dir/config.yaml";

    $output->diag("Writing config to $config_path") if $self->{print_output};

    open my $fh, '>', $config_path or croak "Cannot write config: $!";
    print $fh $config;
    close $fh;

    # Create the database
    $self->_setup_database();

    # Start persephone
    return $self->_start_persephone();
}

sub _start_persephone {
    my $self = shift;

    my $hs_dir = $self->{hs_dir};
    my $output = $self->{output};
    my $idx = $self->{hs_index};
    my $binary = "$self->{bindir}/persephone";

    unless (-x $binary) {
        croak "Persephone binary not found at $binary";
    }

    my @command = ($binary);

    $output->diag("Starting persephone: @command") if $self->{print_output};
    $output->diag("Working directory: $hs_dir") if $self->{print_output};

    return $self->_start_process_and_await_connectable(
        setup => [
            chdir => $hs_dir,
        ],
        command => [ @command ],
        connect_host => $self->{bind_host},
        connect_port => $self->{ports}{client},
        name => "persephone-$idx",
    );
}

sub _setup_database {
    my $self = shift;
    my $port = $self->{ports}{client};
    my $db_name = "persephone_sytest_$port";
    my $output = $self->{output};

    $output->diag("Setting up database $db_name") if $self->{print_output};

    # Drop existing database if it exists (clean slate for each test)
    system("dropdb -U postgres --if-exists $db_name 2>/dev/null");

    # Create fresh database
    my $ret = system("createdb -U postgres $db_name 2>/dev/null");
    if ($ret != 0) {
        $output->diag("Warning: createdb returned $ret for $db_name");
    }
}

sub _cleanup {
    my $self = shift;
    my $port = $self->{ports}{client};
    my $db_name = "persephone_sytest_$port";

    # Clean up database
    system("dropdb -U postgres --if-exists $db_name 2>/dev/null");

    $self->SUPER::_cleanup(@_) if $self->can('SUPER::_cleanup');
}

# Port accessors required by SyTest
sub secure_port {
    my $self = shift;
    return $self->{ports}{federation};
}

sub unsecure_port {
    my $self = shift;
    return $self->{ports}{client};
}

sub federation_port {
    my $self = shift;
    return $self->secure_port;
}

sub federation_host {
    my $self = shift;
    return $self->{bind_host};
}

sub server_name {
    my $self = shift;
    return $self->{bind_host} . ":" . $self->secure_port;
}

sub public_baseurl {
    my $self = shift;
    return "http://$self->{bind_host}:" . $self->unsecure_port;
}

sub print_output {
    my $self = shift;
    return $self->{print_output};
}

1;
