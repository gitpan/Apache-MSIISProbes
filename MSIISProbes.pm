package Apache::MSIISProbes;

use strict;
use vars qw($VERSION $VERSION_DATE);

use Apache::Constants qw(OK DECLINED FORBIDDEN);
use Mail::Sendmail;
use Net::DNS;
use Cache::FileCache;
use Time::Zone;

$VERSION = 1.08;
$VERSION_DATE = 'December 6, 2001';

# ----------------------------------------------------------
# BEGIN USER-CONFIGURABLE OPTIONS
# ONLY change these options!

# Shall our debugging be verbose?
# Set to '1' to log each attempt. Set to '2' to log all mail failures.
# Set to '3' to log everything! Set to '0' for silence.
my $DEBUG = 1;

# What "From:" header should be inserted into outgoing e-mail?
my $from_address = 'you@example.com';

# Do you want to know when one of these alerts has been sent?
# If so, put your address here.
my $cc_address = '';

# Indicate whether the cache should expire or not. If we want to track
# the number of attempts per IP address (and thus send multiple copies
# of the mail) we never expire the cache (this is the default behavior).
# If we want to be less noisy we only send mail once per period.

# set $store to false to only send one message per IP per period
# set $store to true to send messages for every attempt
my $store = 1;

# If $store is false we must specify when to purge the cache: default
# value is one day (86400 seconds).
my %cache_options = $store ? '' : ('default_expires_in' => 86400);

# Shall we send mail only to the SOA contact and abuse@ the SOA domain,
# or shall we also send it to various addresses at the MX for the IP address?
my $soa_only = 0;
 
# List of regexps that should be ignored
my @ignore_ip = ('192\.168\..*', '10\..*');

# END USER-CONFIGURABLE OPTIONS
# ------------------------------------------------------------

my $security_focus_address = 'aris-report@securityfocus.com';
my $module_url = 'http://www.tonkinresolutions.com/software/perl/Apache/MSIISProbes/';

sub handler {
	# Get Apache request/response object
	my $r = shift;
	my %args = $r->args;

	# Get the server name
	my $s = $r->server();
	my $server_name = $s->server_hostname();

	# Stats only?
	if ($args{stats}) {
		$cache_options{'namespace'} = $args{stats};
		my $file_cache = new Cache::FileCache(\%cache_options);
		my %count;
		foreach my $ip ($file_cache->get_identifiers) {
			$count{$ip} = $file_cache->get($ip);
		}
		print "<HTML><PRE>Statistics for the MSIISProbes.pm cache for the $args{stats} worm on $server_name:\n\n";
		foreach my $ip (sort { $count{$b} <=> $count{$a} } keys %count) {
			print "$ip\t$count{$ip}\n";
		}
		print "</PRE></HTML>";
		return OK;
	}

	# Create a DNS resolver, which we'll need no matter what.
	my $res = new Net::DNS::Resolver;
	$res->tcp_timeout(20);

	# ------------------------------------------------------------
	# Open the cache of already-responded-to IP addresses,
	# which we're going to keep in /tmp, just for simplicity.
	#
	# Use the environment var set by Apache to decide which part
	# of the cache to use
	my $worm_name = $r->dir_config('worm_name');
	$cache_options{'namespace'} = $worm_name || 'Default';
	my $file_cache = new Cache::FileCache(\%cache_options);

	unless ($file_cache) {
		$r->log_error("MSIISProbes: Could not instantiate FileCache.  Exiting.");
		return DECLINED;
	}

	# Get the HTTP client's IP address.  We'll use this to
	#  send mail to the people who run the domain.
	my $remote_ip_address = $r->get_remote_host();

	# If we don't have the remote IP address, then we cannot send mail
	# to the remote server, can we?  Let's just stop now, while we're at it.
	unless (defined $remote_ip_address) {
		$r->warn("MSIISProbes: Undefined remote IP address!  Exiting.");
		return DECLINED;
	}

	# If we have the remote IP address, then check to see
	# if it's in our cache.
	my $count = $file_cache->get($remote_ip_address);

	# We update the cache with the new count no matter what,
	# although the count may be cleared (if the mail fails)
	$file_cache->set($remote_ip_address, ++$count);

	if ($count > 1) {
		if ($store) {
			# We go ahead anyway
			$DEBUG && $r->warn("MSIISProbes: Attack number [$count] with [$worm_name] from [$remote_ip_address].  Re-mailing.");
		} else {
			$DEBUG && $r->warn("MSIISProbes: Attack number [$count] with [$worm_name] in the current cache period from [$remote_ip_address].  Exiting.");
			return FORBIDDEN;
		}
	} else {
		$DEBUG && $r->warn("MSIISProbes: Attack number [$count] with [$worm_name] from [$remote_ip_address]. Mailing.");
	}

	# If the remote address matches our ignore list, then ignore it
	foreach my $ignore_ip (@ignore_ip) {
		if ($remote_ip_address =~ /^$ignore_ip$/) {
			$DEBUG && $r->warn("MSIISProbes: Detected known IP [$remote_ip_address] (matched [$ignore_ip]).  Exiting.");
			return FORBIDDEN;
		}
	}

	# ------------------------------------------------------------
	# If we only have the IP address (rather than the hostname), then get the
	# hostname.  (We can't look up the MX host for a number, only a name.)

	my $remote_hostname = $remote_ip_address;

	# If the IP address is numeric, then look up its name
	if ($remote_ip_address =~ /^[\d.]+$/) {
		my $dns_query_response = $res->search($remote_ip_address);
		if ($dns_query_response) {
			foreach my $rr ($dns_query_response->answer) {
				# All of the records we retrieve should be PTR records,
				# since we're doing an IP-to-hostname lookup.
				next unless $rr->type eq "PTR";
				# Once we know this is a PTR, we can grab its name
				$remote_hostname = $rr->rdatastr;
			}
		} else {
			my $dns_error = $res->errorstring;
			$DEBUG && $r->warn("MSIISProbes: Failed DNS lookup of [$remote_ip_address] (error: [$dns_error])");
		}
	}

	# ------------------------------------------------------------
	# Send e-mail to SecurityFocus.com, which is going to
	# deal with all of this stuff automatically
	#
	# If we are storing a count per IP, we only send this mail the first time.
	# If we are purging the cache, we send it once per period.
	my $now = scalar localtime;
	if ($count > 1) {
		$DEBUG && $r->warn("MSIISProbes: Not mailing Security Focus about duplicate IP [$remote_ip_address]");
	} else {
		$DEBUG && $r->warn("MSIISProbes: Sending e-mail to SecurityFocus about IP [$remote_ip_address]");
		my $time_zone_name = uc(tz_name());
		my $sf_message = <<EOT;
$remote_ip_address\t$now $time_zone_name

Brought to you by Apache::MSIISProbes version $VERSION for mod_perl and Apache running on
$server_name.
Information at <$module_url>.
EOT

		my %sf_mail = (
						To	  => $security_focus_address,
						CC	  => $cc_address,
						From	=> $from_address,
						Subject => "$worm_name infection on [$remote_hostname]: Automatic report",
						Message => $sf_message
					   );

		my $sf_sendmail_success = sendmail(%sf_mail);

		unless ($sf_sendmail_success) {
			$DEBUG > 1 && $r->warn("MSIISProbes: Mail::Sendmail returned [$Mail::Sendmail::error].  Exiting.");
			# We want to make sure Security Focus gets the report, so clear the cache entry for this IP
			$file_cache->set($remote_ip_address, 0);
			return DECLINED;
		} else {
			$DEBUG > 2 && $r->warn("MSIISProbes: Sent mail to Security Focus for IP [$remote_ip_address]");
		}
	}

	# ------------------------------------------------------------
	# Get some administrative e-mail addresses for this host
	my $admin_address;

    # Get an email address from the SOA of the domain
    # Courtesy of Sam Phillips' original Code Red Check
    # Patch by Brice D. Ruth
    my $dnsSOA_ipaddr = $remote_ip_address;
    my $dnsSOA_contact;
    my $dnsSOA_ptr_query = $res->query($dnsSOA_ipaddr, "PTR");
    if ($dnsSOA_ptr_query) {
        my $dnsSOA_zone = ($dnsSOA_ptr_query->answer)[0]->ptrdname;
        my @zone;
        my $dnsSOA_soa_query = 0;
        while (!$dnsSOA_soa_query) {
            $dnsSOA_soa_query = $res->query ($dnsSOA_zone, "SOA");
            if ($dnsSOA_zone eq "") { exit 1; };
            @zone = split /\./, $dnsSOA_zone;
            shift @zone;
            $dnsSOA_zone = join '.', @zone;
        }
        
		$dnsSOA_contact = ($dnsSOA_soa_query->answer)[0]->rname;
        $dnsSOA_contact =~ s/\./@/;

		# send to abuse@SOA also	
		unless ($dnsSOA_contact =~ m/^abuse/) {
			my ($junk, $dom) = split('@', $dnsSOA_contact);
			$dnsSOA_contact .= ', abuse@' . $dom;
		}
        $admin_address = $dnsSOA_contact;
        $DEBUG > 1 && $r->warn("MSIISProbes: Using SOA address [$dnsSOA_contact]");
    }

	unless ($soa_only) {
		# Get the MX for this domain.  This is trickier than you might
		# think, since some DNS servers (like my ISP's) give accurate
		# answers for domains, but not for hosts.  So www.lerner.co.il
		# doesn't have an MX, while lerner.co.il does.  So we're going to
		# do an MX lookup -- and if it doesn't work, we're going to break
		# off everything up to and including the first . in the hostname,
		# and try again.  We shouldn't have to get to the top-level
		# domain, but we'll try that anyway, just in case the others don't
		# work.

		my @mx = ();
		my @hostname_components = split /\./, $remote_hostname unless $remote_hostname eq $remote_ip_address;
		my $starting_index = 0;

		# Loop around until our starting index begins at the same location as it would end
		while ($starting_index < @hostname_components) {
			my $host_for_mx_lookup = join('.', @hostname_components[$starting_index .. $#hostname_components]);
			@mx = mx($res, $host_for_mx_lookup);

			if (@mx) {
 				last;
			} else {
				$starting_index++;
			}
		}

		if (! @mx and ! $admin_address) {
			# If we still haven't found any records, then simply return FORBIDDEN, and log an error message
			my $dns_error = $res->errorstring;
			$DEBUG > 1 && $r->warn("MSIISProbes: No MX records or SOA address for [$remote_hostname](error: [$dns_error]).  Exiting.");
			return FORBIDDEN;
		} elsif (@mx) {
			# Grab the first MX record, and assume that it'll work.
			my $mx_host = $mx[0]->exchange;
			$DEBUG > 1 && $r->warn("MSIISProbes: Using MX host [$mx_host]");
			# Send e-mail to the webmaster, postmaster, and administrator, since
			# the webmaster and/or postmaster addresses often doesn't work
			$admin_address .= ', ' if $admin_address;
			$admin_address .= "webmaster\@$mx_host, postmaster\@$mx_host, administrator\@$mx_host";
		}
	}

	# Set the outgoing message
	my $worm_url = $r->dir_config('worm_url') || 'http://www.microsoft.com/technet/default.asp';
	my $request  = $r->the_request;

	my $outgoing_message = <<EOT;

Your Microsoft IIS server (at $remote_ip_address) appears to have been
infected with the $worm_name worm.  It attempted to spread to
our Web server at $now, despite the fact that we run Apache, which is immune.
The requested URI is printed below.

This was attempt number $count from the server at $remote_ip_address
to infect our server. You should immediately view the latest information
and download any available security patches, from <$worm_url>.

Automatically generated by Apache::MSIISProbes version $VERSION for mod_perl
and Apache running on $server_name. Information at <$module_url>.

URI requested:
$request

EOT

	# ------------------------------------------------------------
	# Also send e-mail to the people running the offending host,
	# just in case SecurityFocus takes a while.

	$DEBUG > 1 && $r->warn("MSIISProbes: Sending e-mail to [$admin_address]");

	my %mail = (
				To		=> $admin_address,
				CC		=> $cc_address,
				From	=> $from_address,
				Subject	=> "$worm_name infection on [$remote_hostname]: Automatic report",
				Message	=> $outgoing_message
			   );

	my $sendmail_success = sendmail(%mail);

	if ($sendmail_success) {
		$DEBUG > 2 && $r->warn("MSIISProbes: Sent mail to [$admin_address] for IP [$remote_ip_address]");
		return FORBIDDEN;
	} else {
		$DEBUG > 1 && $r->warn("MSIISProbes: Mail::Sendmail returned [$Mail::Sendmail::error]. Exiting.");
		return DECLINED;
	}
}

# All modules must return a true value
1;

__END__

=pod

=head1 NAME

 Apache::MSIISProbes -
 Responds to worm attacks on Microsoft Internet Information Servers with e-mail warnings.

=head1 SYNOPSIS

 In your httpd.conf, put something similar to the following:

 <Location /default.ida>
   SetHandler perl-script
   PerlHandler Apache::MSIISProbes
   PerlSetVar worm_name CodeRed
   PerlSetVar worm_url http://www.microsoft.com/technet/itsolutions/security/topics/codealrt.asp
 </Location>

=head1 DESCRIPTION

 This Perl module should be invoked whenever the worms it
 knows about attack. We don't have to worry about such
 attacks on non-Windows boxes, but we can be good Internet
 citizens, warning the webmasters on infected machines of the
 problem and how to solve it.

 The module allows the user to add new configuration
 directives as new worms are discovered.

=head1 USAGE

 In your httpd.conf, put directives similar to the following:

 <Location /default.ida>
   SetHandler perl-script
   PerlHandler Apache::MSIISProbes
   PerlSetVar worm_name CodeRed
   PerlSetVar worm_url http://www.microsoft.com/technet/itsolutions/security/topics/codealrt.asp
 </Location>

 <LocationMatch (cmd.exe|root.exe)>
   SetHandler perl-script
   PerlHandler Apache::MSIISProbes
   PerlSetVar worm_name Nimda
   PerlSetVar worm_url http://www.microsoft.com/technet/security/topics/Nimda.asp
 </LocationMatch>

B<Duplicates>

 $store = 1; # Send mail for every attempt
 $store = 0; # Only send mail once per cache period

 Although rumor has it that CodeRed and other similar worms
 only attack a given IP once from a given host, experience
 shows this to be false. You can control the behavior of
 MSIISProbes.pm when it encounters a second or subsequent
 attempt from a given IP address. By default MSIISProbes.pm
 keeps a cache of IP addresses from which an attempt has
 originated, counting attempts per worm from the IP and
 including the count in each message it mails.

 You can override this behavior and send a message only the
 first time a given host attempts to spread the worm in a given
 period by setting the variable $store to a false value. This
 will cause the cache to be cleared at a given interval (by
 default, one day). Mail alerts to the IIS server's
 administrators will be sent only once per cache period.

B<Volume>

 $soa_only = 1; # only send mail to the Start of Authority
 $soa_only = 0; # send mail to address at the IP's MX also

 You can also control the "volume" of the module using the 
 $soa_only flag in the configuration. This variable controls
 the number of addresses to whom e-mail alerts are sent when
 an attempt to infect your server is made. Experience has shown
 that many administrators do not have their MX records set up
 correctly. This can lead to frequent bounced mail when the module
 is in its default configuration ($soa_only = 0).

 If you set $soa_only to a true value, the module will only attempt
 to resolve the Start of Authority for the attacking IP. This will 
 usually result in mail being sent to the SOA contact address plus 
 abuse@ the SOA's domain.

 If you set $soa_only to false, the module will additionally attempt
 to resolve the IP's MX host and send mail to postmaster@, webmaster@,
 and administrator@ that domain. This is a potential total of 5
 messages (plus Security Focus) per attempted infection.

B<Statistics>

 You may wish to see the statistics for the various worms you
 are catching with MSIISProbes.pm. The module supports this
 through setting the value of the query string argument 'stats'
 to one of the worm names you defined in httpd.conf, for
 example like this:

 http://my.server.com/cmd.exe?stats=CodeRed
 or
 http://my.server.com/foo.bar?/c+dir&stats=Nimda

 Just make sure to attache the query string to a URL that will
 be caught by your configuration of the module! Also please note
 that the statistics provided are of your cache, so if you are
 clearing entries after one day the statistics will obviously
 not be cumulative!

=head1 AUTHOR

 Author: Nick Tonkin (nick@tonkinresolutions.com)

 Based on CodeRed.pm by Reuven M. Lerner (reuven@lerner.co.il),
 with ideas from Randal Schwartz, David Young, and Salve J. Nilsen.

=head1 COPYRIGHT

 This code is copyright 2001 Nick Tonkin. All rights reserved.

=head1 LICENSE

 You may distribute this module under the same license as Perl itself.

=head1 CHANGES

 v1.08
 Added the requested URI to the body of the e-mail message sent to
 server admins, since some apparently refuse to take action without
 it (requested by Tom Moore)

 v1.07
 Added $soa_only var to config, allowing more control over the volume.
 Corrected deprecated URL for this module's home page.

 v1.06
 Updated docs to reflect correct httpd.conf sections (Steve Neuharth)

 v1.05
 Fixed bug where mail could get sent to the local server admin if the
 remote IP address doesn't resolve to a host name (in certain environments)
 (reported by Bruce Albrecht)

 Fixed typo in page headline for statistical report (spotted by Alex Vandiver)

 v1.04
 Added code to provide statistics on the Cache (suggested by Paul DuBois)

 v1.03
 Added code to get e-mail for the SOA of the host (Brice D. Ruth)

 Cut the DNS Resolver's timeout to 20 seconds

 v1.02
 Moved the URL for info for each worm into PerlSetVar in httpd.conf

=head1 SEE ALSO

L<Apache>.

=cut
