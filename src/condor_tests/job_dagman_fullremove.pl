#!/usr/bin/env perl
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


use File::Copy;
use Cwd;
#my $LogFile = "buildgahp.log";

#open(OLDOUT, ">&STDOUT");
#open(OLDERR, ">&STDERR");
#open(STDOUT, ">$LogFile") or die "Could not open $LogFile: $!";
#open(STDERR, ">&STDOUT");
#select(STDERR); $| = 1;
#select(STDOUT); $| = 1;

# Allow time for this job to get removed before it exits normally.
sleep(120);

print "Returning error from test job\n";
exit(3);
