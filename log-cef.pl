#!/usr/bin/perl
use Net::Syslogd;
use Net::Syslog;
use Time::Format qw(%time %strftime %manip);
use Net::Domain qw(hostname hostfqdn hostdomain);

# var
$logfile = "/var/log/log-cef";
$localname = hostname();

# ------ startup items
# The syslog server
my $syslogd = Net::Syslogd->new(LocalPort=>'515')
  or die "Error creating Syslogd listener: %s", Net::Syslogd->error;

# The syslog client
my $s=new Net::Syslog(Facility=>'syslog', SyslogHost=>'10.2.75.199');

# Log file for this system
open ( FH, "+>>$logfile" );

# Startup message to ArcSight
# CEF reference
# CEF:0|<vendor>|<product>|<device version|<Signature ID>|<name>|<Severity>|<Extension>
$s->send("CEF:0|mozilla|ossec|1.0|1|ossec syslog to cef process has started on $localname|1|");
print "starting the server process and log to cef\n";

#Loop to capture log messages
while (1) {
  my $message;
  if (!($message = $syslogd->get_message())) { next }
  
  if (!(defined($message->process_message()))) {
    CEFout ( "$0: %s\n", Net::Syslogd->error );
  } else { 
    $rawname = $message->message;
    CEFout ( "R: $rawname" );
    $setnext = 0;
    $getmore = 1;
    @split = $rawname =~ (/^(.*\->[-_\/A-Za-z0-9]+);(.*)/);
    $rawstring0 = $split[0];
    $rawstring1 = $split[1];

    # Cleaning up whitespace
    $rawstring0 =~ s/^\s*//g;
    $rawstring1 =~ s/^\s*//g;
    # ----------rawmstring 0
    # regex for the first message
    if ( $rawstring0 =~ /^([-_A-Za-z0-9]+) ossec: Alert Level: (\d+); Rule: (\d+)\s-\s(.*);\sLocation: (.*)$/  ) { 
      $ossec_mgr = $1; #ext (done)
      $alert_level = $2; #cef_header
      $alert_rule_id = $3; #cef_header
      $evt_name = $4; #cef_header
      $evt_location = $5; 
    } else {
      $setnext = 1;
      $setnext_breakpoint = "rawstring0: initial regex:";
    }
    @loco_blob = split ( /\->/, $evt_location, 2);
    $dst_proc_name = $loco_blob[1]; #ext
    # ipsectools01->/var/log/secure || (natasha) 10.8.75.5->/var/log/secure || ipsectools01->/var/log/secure
    $extout = "cs1Label=ossec_manager cs1=$ossec_mgr"; 
    if ( $loco_blob[0] =~ /^([-_A-Za-z0-9]+)$/ ) {
        $dhost = $1;
	$extout = $extout . " dproc=$dst_proc_name dhost=$dhost";
    }
    if ( $loco_blob[0] =~ /^\((\w+)\)\s(\d+.\d+.\d+.\d+)$/ ) {
	$dhost = $1;
	$dst = $2;
	$extout = $extout . " dproc=$dst_proc_name dhost=$dhost dst=$dst";
    }
    
    # ----------rawstring 1
    # regex and handling for second raw message
    if ( $rawstring1 =~ /^srcip:\s(\d+.\d+.\d+.\d+);\suser:\s(.*);(.*)/ ) {
      $srcip = $1;
      $duser = $2;
      $mess = $3;
      $mess =~ s/^\s*//g;
      $extout = $extout . " src=$srcip duser=$duser";
      print "D: \$extout $extout\n" if ( $rawstring1_debug =~ /1/);
    } elsif ( $rawstring1 =~ /^user:\s([-_A-Za-z0-9]+);\s+(.*)/ ) {
      $duser = $1;
      $mess = $2;
      $mess =~ s/^\s*//g;
      $extout = $extout . " duser=$duser";
    } else {
      $mess = $rawstring1;
      $getmore = 1;
    }
    if ( $mess =~ /(\w+)\[\d+\]:/ ) { # try to grab process which is creating these logs
        $app = $1;
	$extout = $extout . " app=$app";
    }

    ##########
    # The Gather More Section (Reading the mess field)
    ##########
    if ( $getmore =~ /1/ ) { 
      if ( $mess =~ /user\s([-_A-Za-z0-9]+)\s/ ) { #trying to grab a user name
	$duser = $1;
	$extout = $extout . " duser=$duser";
      }
      if ( $mess =~ /ossec: (.*): \'([-_A-Za-z0-9]+)-(\d+.\d+.\d+.\d+)\'/ ) { # grab out details on system for ossec messages
	$shost = $2;
	$src = $3;
	$extout = $extout . " shost=$shost src=$src";
      }
    }

    $extout = $extout . " msg=$mess";

  if ( $setnext =~ /1/ ) {
    print "PARSE ERROR: $setnext_breakpoint R: $rawname\n";
    print "--------------------------END\n";
    next;
  }
  
  # alert number change for $sev
  if ( $sev == 9 )  { $sev = 8; }
  if ( $sev == 10 )  { $sev = 9; }
  if ( $sev > 10 ) { $sev = 10; }
  
  # build the CEF message
  $cefout = "CEF:0|mozilla|ossec|1.0|$alert_rule_id|$evt_name|$alert_level|$extout";
  #send out the CEF message
  $s->send("$cefout");
  #send message to log
  CEFout ( "C: $cefout\n--------------------------END");
  }
}

# close out file handle
close ( FH );

sub CEFout {
  my $output = shift;
  my $t_stamp=$time{'Mon dd hh:mm:ss'};
  print "$output\n";
  print ( FH "$t_stamp $output\n" );
}

