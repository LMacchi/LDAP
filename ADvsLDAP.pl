#!/usr/bin/perl
# AD contains all the users in the company. It has a group for Linux users.
# LDAP contains all the linux users.
# The contents of AD linux group has to be the same as the full LDAP.
# I'm lazy so I hardcoded all the settings. Reading from console or parsed by arguments should be an easy change.
# I'm aware of how dirty it is, not very proud of it. There, I said it.
# https://github.com/LMacchi

use strict;
use Net::LDAP;
use Net::LDAPS;
use Data::Dumper;
use Getopt::Long qw(:config no_ignore_case);
use Array::Utils qw(:all);
use MIME::Lite;
use MyLdap;

# Variables for Active Directory
my $AD_hostname = "ad.company.com";
my $AD_port = 389;
my $AD_manager = 'adLinux';
my $AD_pwd = "password";
my $AD_base = "dc=company,dc=com";
my $AD_filter = '(memberOf=CN=LinuxGroup,dc=company,dc=com)';

# Variables for LDAP
my $ldap_hostname = "ldap.company.com";
my $ldap_port = 636;
my $ldap_manager = 'cn=root,dc=company,dc=com';
my $ldap_pwd = "password";
my $ldap_base = "dc=company,dc=com";
my $ldap_filter = '(uid=*)';

# Global variables for Net::LDAP
my $debug = 0;
my $timeout = 60;
my $version = 3;

# Internal variables
my @AD_disabled_users;
my @AD_active_users;
my %AD_unknown_users;
my @ldap_disabled_users;
my @ldap_active_users;
# List of users exempt of checks against AD
my @ldap_service_accounts = ( "syncuser", "release" );

my $admins_mail = 'linuxadmins@company.com';
#my $admins_mail = 'lmacchi@company.com';

# Open log file
my $today = MyLdap::dateToday();
print "Running $0 - $today\n";

# Connect to AD and retrieve users
my $AD = MyLdap::ldap_connect ($AD_hostname, $AD_port, $AD_manager, $AD_pwd);
my $msg = MyLdap::ldap_search ($AD, $AD_base, $AD_filter);
MyLdap::ldap_unbind($AD);

# Parse results
my @entries = $msg->entries;
if (!@entries) {
	print "No entries found in $AD_hostname\n";
	exit 1;
}

my %controls = MyLdap::ADGetAttrUser (\@entries, "userAccountControl");
if (!%controls) {
	print "No entries found in $AD_hostname with attribute userAccountControl\n";
}

# This will be used later to create users
my %displayNames = MyLdap::ADGetAttrUser (\@entries, "displayName");

foreach my $user (keys %controls) {
	if ($controls{$user} == 514) {
                # Add to disabled users array
                push (@AD_disabled_users, lc($user));
	} elsif ($controls{$user} == 512) {
		push(@AD_active_users, lc($user));
	} else {
		$AD_unknown_users{$user} = $controls{$user};
	}
}

# Uncomment for debugging
#foreach my $user (@AD_active_users) {
#	print "AD user $user is active\n";
#}

#foreach my $user (@AD_disabled_users) {
#        print "AD user $user is disabled\n";
#}

#foreach my $user (keys %AD_unknown_users) {
#        print "AD Unknown user $user has userAccountControl: $AD_unknown_users{$user}\n";
#}

# We have now a list of active, disabled and others from Active Directory.
# Time to do the same for Ldap
my $ldaps = MyLdap::ldaps_connect ($ldap_hostname, $ldap_port, $ldap_manager, $ldap_pwd);
my $msg = MyLdap::ldap_search ($ldaps, $ldap_base, $ldap_filter);
MyLdap::ldap_unbind($ldaps);

# Parse results
my @entries = $msg->entries;
if (!@entries) {
        print "No entries found in $ldap_hostname\n";
        exit 1;
}

my %shells = MyLdap::ldapGetAttrUser (\@entries, "loginShell");
# Used later to create users
my @uids = MyLdap::getAttr (\@entries, "uidNumber");

if (!%shells) {
        print "No entries found in $ldap_hostname with attribute loginShell\n";
}

foreach my $user (keys %shells) {
        if ($shells{$user} =~ /false/) {
		push (@ldap_disabled_users, $user);
        } else {
                push(@ldap_active_users, $user);
        }
}

#foreach my $ldap_user (@ldap_active_users) {
#        print "LDAP user $ldap_user is active\n";
#}

#foreach my $ldap_user (@ldap_disabled_users) {
#        print "LDAP user $ldap_user is disabled\n";
#}


# Now we have arrays for AD and LDAP, active and disabled users. Let's do some checks
# Check 1: Is there any inactive user in AD active in LDAP?
# These ones need to be disabled
print "List of inactive users in AD active in LDAP:\n";
my @users_to_disable = intersect (@AD_disabled_users,@ldap_active_users);
if (!@users_to_disable) {
	print "\tNo disabled AD users are active in LDAP. All is good with the world.\n";
} else {
	my $ldaps = MyLdap::ldaps_connect ($ldap_hostname, $ldap_port, $ldap_manager, $ldap_pwd);
	MyLdap::disable_users(\@users_to_disable, $ldaps, $ldap_base);
	MyLdap::ldap_unbind($ldaps);
}

# Check 2: Is there any active user in AD that isn't in LDAP?
# These ones need to be created/enabled
print "List of active users in AD that aren't in LDAP:\n";
my @users_in_AD_not_LDAP = array_minus (@AD_active_users, @ldap_active_users);
my @users_to_update = array_minus (@users_in_AD_not_LDAP, @ldap_service_accounts);
if (!@users_to_update) {
        print "\tNo users in AD need to be created in LDAP.\n";
} else {
	my @users_to_enable = intersect (@users_to_update, @ldap_disabled_users);
	my @users_to_create = array_minus (@users_to_update, @users_to_enable);
	if ((@users_to_create) or (@users_to_enable)) {
		my $ldaps = MyLdap::ldaps_connect ($ldap_hostname, $ldap_port, $ldap_manager, $ldap_pwd);
		MyLdap::enable_users(\@users_to_enable, $ldaps, $ldap_base);
		MyLdap::createLdapUsers(\@users_to_create, \%displayNames, \@uids, $ldaps);
		MyLdap::ldap_unbind($ldaps);
	}
}

# Check 3: Is there any active user in LDAP that isn't in AD?
# These ones need to be added to AD subgroup or disabled
print "List of active users in LDAP not found in AD:\n";
my @users_in_LDAP_not_AD = array_minus (@ldap_active_users, @AD_active_users);
my @users_to_validate = array_minus (@users_in_LDAP_not_AD, @ldap_service_accounts);
if (!@users_to_validate) {
	print "\tNo users in LDAP are absent in AD.\n";
} else {
	MyLdap::verify_users(\@users_to_validate, $admins_mail);
}

$today = MyLdap::dateToday();
print "Script Finished - $today\n";
