#!/usr/bin/env perl
# Install Perl dependencies for Persephone sytest plugin
# Based on valkum/sytest_conduit/install-deps.pl

use strict;
use warnings;
use 5.014;

use Getopt::Long;

my $notest = 0;
my $dryrun = 0;

GetOptions(
    'T|notest' => \$notest,
    'n|dryrun' => \$dryrun,
) or die "Usage: $0 [-T|--notest] [-n|--dryrun]\n";

# Check if a module is installed
sub check_installed {
    my ($module, $want_version) = @_;

    my $check_cmd = qq{perl -M$module -e 'print \$${module}::VERSION // "0"' 2>/dev/null};
    my $installed_version = `$check_cmd`;

    return 0 if $? != 0;
    return 1 unless defined $want_version;

    # Simple version comparison
    return $installed_version ge $want_version;
}

# Install a module if not present
sub requires {
    my ($module, $version) = @_;

    if (check_installed($module, $version)) {
        say "  $module is already installed";
        return;
    }

    my $install_spec = $version ? "$module~$version" : $module;

    if ($dryrun) {
        say "  Would install: $install_spec";
        return;
    }

    say "  Installing: $install_spec";

    my @cmd = ('cpanm');
    push @cmd, '--notest' if $notest;
    push @cmd, $install_spec;

    system(@cmd) == 0 or warn "Failed to install $module: $?\n";
}

say "Installing Persephone sytest dependencies...";

# Load CPAN config
eval { require CPAN; CPAN::HandleConfig->load };

# Read cpanfile and install dependencies
my $cpanfile = 'cpanfile';
if (-f $cpanfile) {
    open my $fh, '<', $cpanfile or die "Cannot open $cpanfile: $!";
    while (<$fh>) {
        chomp;
        next if /^\s*#/ || /^\s*$/;

        if (/^requires\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?\s*;?\s*$/) {
            requires($1, $2);
        }
    }
    close $fh;
}

say "Done installing dependencies.";
