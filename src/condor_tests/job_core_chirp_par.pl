#! /usr/bin/env perl
##**************************************************************
##
## Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
## University of Wisconsin-Madison, WI.
## 
## Licensed under the Apache License, Version 2.0 (the "License"); you
## may not use this file except in compliance with the License.  You may
## obtain a copy of the License at
## 
##    http://www.apache.org/licenses/LICENSE-2.0
## 
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
##**************************************************************

use CondorTest;
use strict;
use warnings;


my $cmd = $ARGV[0];
my $debuglevel = 1;

CondorTest::debug("Submit file for this test is $cmd\n",$debuglevel);

my $testdesc =  'Basic Parallel - Parallel U';
my $testname = "job_core_chirp_par";

my $aborted = sub {
	my %info = @_;
	my $done;
	die "Abort event not expected!\n";
};

my $held = sub {
	my %info = @_;
	my $cluster = $info{"cluster"};

	die "Held event not expected.....\n";
};

my $executed = sub
{
	my %args = @_;
	my $cluster = $args{"cluster"};

	CondorTest::debug("Parallel job executed\n",$debuglevel);
};

my $success = sub
{
	CondorTest::debug("Success: Parallel Test ok\n",$debuglevel);
};

CondorTest::RegisterExitedSuccess( $testname, $success);
CondorTest::RegisterExecute($testname, $executed);

if( CondorTest::RunTest($testname, $cmd, 0) ) {
	CondorTest::debug("$testname: SUCCESS\n",$debuglevel);
	exit(0);
} else {
	die "$testname: CondorTest::RunTest() failed\n";
}

