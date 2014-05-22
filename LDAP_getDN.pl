#!/usr/bin/perl
# Given an uid it return the full CN
use strict;
use Net::LDAPS;
use Data::Dumper;
use Getopt::Long qw(:config no_ignore_case);
use MyLdap;

# Variables
my $ldap_hostname = "ldap.company.com";
my $ldap_port = 636;
my $ldap_manager = "cn=root,dc=company,dc=com";
my $ldap_pwd = "password";
my $ldap_base = "dc=company,dc=com";

my $debug = 0;
my $timeout = 60;
my $version = 3;
my $uid;

# Get arguments
my $result = GetOptions (
	'u|uid=s'	=> \$uid,
);

if (!$uid) {
	usage();
}

my $filter = "(uid=$uid)";
my $ldaps = MyLdap::ldaps_connect ($ldap_hostname, $ldap_port, $ldap_manager, $ldap_pwd);
my $msg = MyLdap::ldap_search ($ldaps, $ldap_base, $filter);
MyLdap::ldap_unbind($ldaps);

my @entries = $msg->entries;
if (!@entries) {
	print "No entries found for user $uid in $ldap_hostname\n";
	exit 1
}

my @dns = MyLdap::getDN(\@entries);
foreach my $dn (@dns) {
	print "User $uid dn is [$dn]\n";
}

exit 0;

sub usage {
        print "Usage\n";
        print "\t$0 -u ldap_user\n";
        print "\n";
        print "\tReturns an user full dn from LDAP\n";
        exit 3;
}

