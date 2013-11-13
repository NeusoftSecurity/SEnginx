#!/usr/bin/perl

# (C) Paul Yang

# Tests for web defacement file protection kernel module.

###############################################################################

use warnings;
use strict;

use Test::More;

my $test_dir = "/tmp/wdfp";
my $test_file = "dummy";
my $proc_syscall_table = "/proc/sys/wdfp/syscall_table_addr";
my $proc_protection_path = "/proc/sys/wdfp/protection_path";
my $proc_switch = "/proc/sys/wdfp/enabled";
my $syscall_addr;


# mkdir and prepare test files
die "Can't prepare test file $test_file in $test_dir"
    unless &prepare_files($test_dir, $test_file);

# get environ variables
# load kernel module
my $module_path = $ENV{'TEST_WDFP_MOD_PATH'};
if (!$module_path) {
    $module_path = "../../3rd-party/ngx_http_web_defacement/kernel";
}

ok(system("/sbin/insmod $module_path/wdfp.ko") == 0, "Insert wdfp module into kernel");

# test the proc interface of this module
# 1) set syscall table address
# 2) set protection path
# 3) enable the protection
$syscall_addr = &get_syscall_addr();

ok($syscall_addr, "Get syscall address");

ok(&set_syscall_table($syscall_addr, $proc_syscall_table), "Set syscall table address");
ok(&set_protection_path($test_dir, $proc_protection_path), "Set protection path");
ok(&enable_protection($proc_switch), "Enable protection");

# try to write data into $test_file, should be failed
ok(&write_content($test_dir, $test_file) > 0, "Change file content under protection");
ok(&delete_content($test_dir, $test_file) > 0, "Delete file under protection");

# disable the protection
ok(&disable_protection($proc_switch), "Disable protection");

# try to write data into $test_file, should be successful
ok(&write_content($test_dir, $test_file) == 0, "Change file content under no protection");

# unload the module
ok(system("/sbin/rmmod wdfp") == 0, "Remove wdfp module from kernel");

&cleanup_files($test_dir, $test_file);

done_testing();


# functions
sub set_syscall_table {
    my ($syscall_addr, $proc_syscall_table) = @_;

    system("echo \"$syscall_addr\" > $proc_syscall_table") == 0;
}

sub set_protection_path {
    my ($test_dir, $proc_protection_path) = @_;

    system("echo \"$test_dir\" > $proc_protection_path") == 0;
}

sub enable_protection {
    my ($proc_switch) = @_;

    system("echo \"1\" > $proc_switch") == 0;
}

sub disable_protection {
    my ($proc_switch) = @_;

    system("echo \"0\" > $proc_switch") == 0;
}

sub prepare_files {
    my ($test_dir, $test_file) = @_;

    return -1 unless mkdir $test_dir;
    return -1 unless open(OUT, ">", "$test_dir/$test_file");

    print OUT "some text";

    close OUT;

    1;
}

sub cleanup_files {
    my ($test_dir, $test_file) = @_;
    unlink "$test_dir/$test_file";
    rmdir $test_dir;
}

sub write_content {
    my ($test_dir, $test_file) = @_;

    return -1 unless open(OUT, ">", "$test_dir/$test_file");

    print OUT "some more text";

    close OUT;

    open(IN, "$test_dir/$test_file");
    while (<IN>) {
        if (/some more text/) {
            close IN;
            return 0;
        }
    }

    close IN;

    0;
}

sub delete_content {
    my ($test_dir, $test_file) = @_;

    unlink "$test_dir/$test_file";
}

sub get_syscall_addr {
    my $raw = `grep sys_call_table /boot/System.map-\`uname -r\``;

    if ($raw =~ /^(.*) .* sys_call_table\n/) {
        return $1;
    }

    undef;
}
