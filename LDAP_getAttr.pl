#!/usr/bin/perl
# Script to bind to ldap in port 389 (unsecure)
# All the settings are hardcoded, it shouldn't be difficult to extend them as to take them by console
# Or even read it from user input.
# I use a custom perl library, MyLdap. I'm so original.
# https://github.com/LMacchi

use strict;
use Net::LDAPS;
use Data::Dumper;
use Getopt::Long qw(:config no_ignore_case);
use MyLdap;

# Variables for LDAP
my $LDAP_hostname = "ldap.company.com";
my $LDAP_port = 389;
my $LDAP_manager = 'ldapadmin';
my $LDAP_pwd = "password";
my $LDAP_base = "dc=company,dc=com";
my $debug = 0;
my $timeout = 60;
my $version = 3;
my ($uid, $attr);

# Get arguments
my $result = GetOptions (
	'u|uid=s'		=> \$uid,
	'a|attr|attribute=s'	=> \$attr,
);

if ((!$uid) or (!$attr)) {
	usage();
}

# AD usually uses sAMAccountName attribute, LDAP usually uses uid. 
my $LDAP_filter = "sAMAccountName=$uid";

my $LDAP = MyLdap::ldap_connect ($LDAP_hostname, $LDAP_port, $LDAP_manager, $LDAP_pwd);
my $msg = MyLdap::ldap_search ($LDAP, $LDAP_base, $LDAP_filter);
MyLdap::ldap_unbind($LDAP);

my @entries = $msg->entries;

if (!@entries) {
	print "No entries found for user $uid in $LDAP_hostname\n";
	exit 1
}

my @values = MyLdap::getAttr (\@entries, $attr);

foreach my $value (@values) {
	print "User $uid $attr is [$value]\n";
}

exit 0;

sub usage {
        print "Usage\n";
        print "\t$0 -u LDAP_user -a LDAP_attr\n";
        print "\n";
        print "\tReturns an user's attribute from LDAP\n";
        exit 3;
}

