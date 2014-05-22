#!/usr/bin/perl
# This is a library where I stored the most used pieces of code.
# It isn't pretty, but it does the job.
# https://github.com/LMacchi

package MyLdap;

require Exporter;
@ISA = qw(Exporter);

# Connect to ldap unsecured
# Returns ldap object
# Arguments are host, port, manager and password
sub ldap_connect {
	my ($host, $port, $manager, $pwd) = @_;

	# Start the object ldap
	my $ldap = Net::LDAP->new($host,
	        port 	=> $port,
        	debug   => $debug,
	        timeout => $timeout,
        	version => $version,
	) or die "$@";

	# Bind
	$ldap ->bind ($manager,
        	password => $pwd,
	) or die "$@";

	return $ldap;
}

# Connect to ldap secure
# Returns ldap object
# Arguments are host, port, manager and password
sub ldaps_connect {
        my ($host, $port, $manager, $pwd) = @_;

        # Start the object ldap
        my $ldap = Net::LDAPS->new($host,
                port    => $port,
                debug   => $debug,
                timeout => $timeout,
                version => $version,
        ) or die "$@";

        # Bind
        $ldap ->bind ($manager,
                password => $pwd,
        ) or die "$@";

        return $ldap;
}

# LDAP search, returns results
# Arguments are ldap object, base and filter
sub ldap_search {
	my ($ldap, $base, $filter) = @_;

	my $msg = $ldap->search(
        	base	=> $base,
        	scope	=> "subtree",
        	filter	=> $filter,
	);
	
	return $msg;
}

# This sub unbinds the object from ldap
# Argument is an ldap object
sub ldap_unbind {
	my $ldap = $_[0];

	# Unbind
	$ldap->unbind;
}

# Given an user entry, returns the uid full dn
# Argument is string user entry
sub getDN {
	my ($entries) = @_;
	my @entries = @{$entries};
	my @results;
	if (!@entries) {
        	print "No entries found\n";
		return 0;
	} else {
		# Retrieve DN
		foreach my $entry (@entries) {
			my $value = $entry->dn;
			push (@results, $value);
		}
	}
	return @results;
}

# Given an user entry returns the requested valid ldap attribute
# Arguments are string user entry, and attribute name
sub getAttr {
	my ($entries, $attr) = @_;
	my @entries = @{$entries};
	my @results;
	if (!@entries) {
                print "No entries found\n";
                return 0;
        } else {
		# Retrieve attr
		foreach my $entry (@entries) {
			my $value = $entry->get_value("$attr");
			push (@results, $value);
		}
	}
	return @results;
}

# This sub returns a hash with user and attr value
# Arguments are array user entry and attribute string
sub ADGetAttrUser {
        my ($entries, $attr) = @_;
        my @entries = @{$entries};
        my %results;
        if (!@entries) {
                print "No entries found\n";
                return 0;
        } else {
                # Retrieve attr
                foreach my $entry (@entries) {
			my $user = $entry->get_value("sAMAccountName");
                        my $value = $entry->get_value("$attr");
			$results{$user} = $value;
                }
        }
        return %results;
}

# This one is identical to the other one but uses uid instead of sAMAaccountName
sub ldapGetAttrUser {
        my ($entries, $attr) = @_;
        my @entries = @{$entries};
        my %results;
        if (!@entries) {
                print "No entries found\n";
                return 0;
        } else {
                # Retrieve attr
                foreach my $entry (@entries) {
                        my $user = $entry->get_value("uid");
                        my $value = $entry->get_value("$attr");
                        $results{$user} = $value;
                }
        }
        return %results;
}

# Look for the biggest uid and adds one.
# Argument is an array of uids and it returns an integer
sub getNextUid {
	my @uids = @_;
	my $chosen = 0;
	foreach my $uid (@uids) {
		# Service accounts have uids > 20000
		if (($uid <19999) and ($uid > $chosen)) {
			$chosen = $uid;
		}
	}
	# $chosen has the higher uid
	return ($chosen + 1);
}

# This script disables users in LDAP
# by updating the loginShell to /bin/false
sub disable_users {
        my ($users, $ldap, $base) = @_;
        my @users = @{$users};
        foreach my $user (@users) {
                my $filter = "(uid=$user)";
                my $msg = ldap_search ($ldap, $base, $filter);

                # Parse results
                my @entries = $msg->entries;
                if (!@entries) {
                        print "No entries found for user $user in LDAP\n";
                        return 0;
                }

                # Retrieve DN
		my @user_dn = getDN (\@entries, $user);
		# I should have only one dn
		if (scalar @user_dn != 1) {
			print "No entries found for user $user in LDAP\n";
		}

                # Change login shell to /bin/false
                $msg = $ldap->modify ( $user_dn[0],
                        replace => { loginShell => '/bin/false' }
                );

                print "User $user (ldap: $user_dn[0]) has been disabled in LDAP\n";
		return 1;
        }
}

# This script enables users in LDAP
# by updating the loginShell to /bin/bash
# It basically undoes what the disable_users sub does
sub enable_users {
	my ($users, $ldap, $ldap_base) = @_;
	my @users = @{$users};
	foreach my $user (@users) {
		my $filter = "(uid=$user)";
		my $msg = ldap_search ($ldap, $ldap_base, $filter);

		# Parse results
		my @entries = $msg->entries;
		if (!@entries) {
        		print "No entries found user $user in LDAP\n";
        		return 0;
		}

		my @user_dn = getDN (\@entries, $user);
		if (scalar @user_dn != 1) {
                        print "No entries found for user $user in LDAP\n";
                }

		# Change login shell to /bin/bash
		$msg = $ldap->modify ( $user_dn[0],
        		replace => { loginShell => '/bin/bash' }
		);

		print "User $user (ldap: $user_dn[0]) has been enabled in LDAP\n";
		return 1;
	}

}

# This script creates users in LDAP
# by taking information from AD
# Does not assign a group, so user won't have access to any servers
# until an admin manually assigns a group
sub createLdapUsers {
	my ($users, $data, $uids, $ldap) = @_;
	my @users = @{$users};
	my %data = %{$data};
	my @uids = @{$uids};
	my $uidNumber = getNextUid(@uids);
	foreach my $user (@users) {
		my $displayName = $data{$user};
		my $branch = "ou=Uncategorized,ou=Users,dc=company,dc=com";
		my $cn;
		# Parse displayName: Macchi, Laura to get sn=Laura Macchi
		if ($displayName =~ /([a-zA-Z]+)\, ([a-zA-Z]+)/) {
			$cn = $2." ".$1;
		} else {
			print "User $displayName cannot be created - displayName has incorrect format\n";
			next;
		}
		my $dn = "uid=$user,$branch";
		my $msg = $ldap -> add ($dn,
			attr => [ 	'cn'		=> $cn,
					'homeDirectory'	=> "/users/$user",
					'uid'		=> $user,
					'uidNumber'	=> $uidNumber,
					'gecos'		=> $cn,
					'loginShell'	=> '/bin/bash',
					'gidNumber'	=> 0,
					'objectClass'	=> [ "top", "account", "posixAccount", "shadowAccount" ],
			]
		);
		print "\tUser $dn has been added to LDAP\n";
		$uidNumber++;
	}
}

# This script notifies admins via email
# about users active in ldap but not in AD
sub verify_users {
	my ($users, $admins_mail) =@_;
	my @users = @{$users};

	if (!@users) {
		print "No users found to notify about\n";
		return 1;
	}

        my $subject = "LDAP: Admin action needed";
        my $txt = "LDAP checked its users against AD today and found users that are in LDAP but not in AD.\n\n";
        $txt .= "List of user(s) detected:\n\n";
	foreach my $u (@users) {
		$txt .= "\t$u\n";
	}
	$txt .= "\nTo remediate this, do <list of actions>. Once this action has been completed, you'll stop receiving this notification.\n\n";
	$txt .= "Love,\n";
	$txt .= "Your friendly LDAP server";

	use MIME::Lite;
	my $email = MIME::Lite->new(
    		From    => 'ldap@company.com',
    		To      => $admins_mail,
    		Subject => $subject,
		Data 	=> $txt,
	);

	$email->send;
	print "Email sent to $admins_mail with lists of users needing manual action\n";
	return 1;
}

# Returns today's date
sub dateToday {
        my($sec, $min, $hour, $day, $mon, $year) = (localtime)[0,1,2,3,4,5];
	$sec = sprintf '%02d', $sec;
	$min = sprintf '%02d', $min;
	$hour = sprintf '%02d', $hour;
        $mon = sprintf '%02d', $mon+1;
        $day   = sprintf '%02d', $day;
        $year = $year+1900;
        my $today = $year."/".$mon."/".$day." ".$hour.":".$min.":".$sec;
        return $today;
}

