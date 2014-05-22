#!/usr/bin/perl
#
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
my $uid;
my $user_dn;

# Get arguments
my $result = GetOptions (
	'u|uid=s'	=> \$uid,
);

if (!$uid) {
	usage();
}

my $ldap_filter = "(uid=$uid)";

# Connect to ldap
my $ldaps = MyLdap::ldaps_connect ($ldap_hostname, $ldap_port, $ldap_manager, $ldap_pwd);
my $msg = MyLdap::ldap_search ($ldaps, $ldap_base, $ldap_filter);

# Parse results
my @entries = $msg->entries;
if (!@entries) {
	print "No entries found in LDAP for user $uid\n";
	exit 1;
}

# Retrieve DN
my @user_dn = MyLdap::getDN (\@entries, $uid);
if (scalar @user_dn > 1) {
	print ("More than one entry found for user $uid in LDAP\n");
}

# Force them to change their password at first login
# The pwdReset attribute sucks, because it is only present when it is enabled
# So we're not going to bother checking if it exists, we're just going to add it
$msg = $ldaps->modify ( $user_dn[0], 
	add => { pwdReset => 'TRUE' }
);

print "pwdReset attribute has been added to $user_dn[0]\n";

MyLdap::ldap_unbind($ldaps);

sub usage {
        print "Usage\n";
        print "\t$0 -u user_uid\n";
        print "\n";
        print "\tSet ldap account to force password reset at first login\n";
        exit 3;
}
