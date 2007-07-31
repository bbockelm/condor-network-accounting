#! /usr/bin/env perl
use CondorTest;

Condor::DebugOff();

$cmd = $ARGV[0];

print "Submit file for this test is $cmd\n";
#print "looking at env for condor config\n";
#system("printenv | grep CONDOR_CONFIG");

$testname = 'Basic EventLog Test';

$aborted = sub {
	my %info = @_;
	my $done;
	print "Abort event not expected!\n";
};

$held = sub {
	my %info = @_;
	my $cluster = $info{"cluster"};

	print "Held event not expected.....\n";
};

$executed = sub
{
	my %args = @_;
	my $cluster = $args{"cluster"};

	CondorTest::RegisterTimed($testname, $timed, 600);
	print "EventLog test executed\n";
};

$timed = sub
{
	die "Test took too long!!!!!!!!!!!!!!!\n";
};

$success = sub
{
	print "Success: EventLog Test ok\n";
};

CondorTest::RegisterExitedSuccess( $testname, $success);
CondorTest::RegisterExecute($testname, $executed);

if( CondorTest::RunTest($testname, $cmd, 0) ) {
	print "$testname: SUCCESS\n";
	exit(0);
} else {
	die "$testname: CondorTest::RunTest() failed\n";
}
