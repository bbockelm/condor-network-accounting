<?php

class CondorQ {

  var $platforms;
  var $pool;

  function CondorQ($pool) {
    // In NMI, crosstests will be listed as 'test'
    if($pool) {
      $this->pool = $pool;
    }

    $this->platforms = Array();
  }

  function _CondorQ() {
    // Destructor
  }


  function add_platform($platform) {
    // Add a new platform to get info about.  Strip off the 'nmi:' prefix.
    array_push($this->platforms, preg_replace("/nmi:/", "", $platform));
  }

  function get_platforms() {
    return $this->platforms;
  }

  function condor_q() {
    // Run condor_q for each registered platform

    // Form the constraint
    $plats = Array();
    foreach ($this->platforms as $platform) {
      array_push($plats, "nmi_target_platform==\"$platform\"");
    }
    $platform_constraint = implode(" || ", $plats);
    $constraint = "($platform_constraint)";

    // Get the output - 1 line per job running
    $output = `/usr/bin/condor_q -global -const '$constraint' -format '%-11s ' 'nmi_target_platform' -format '%-2s ' 'ifThenElse(JobStatus==0,"U",ifThenElse(JobStatus==1,"I",ifThenElse(JobStatus==2,"R",ifThenElse(JobStatus==3,"X",ifThenElse(JobStatus==4,"C",ifThenElse(JobStatus==5,"H",ifThenElse(JobStatus==6,"E",string(JobStatus))))))))' -format "%6d " ClusterId -format " %-14s " Owner -format '%s ' 'nmi_run_type' -format '%-11s ' 'formatTime(QDate,"%0m/%d %H:%M")' -format '%-11s\n' 'formatTime(EnteredCurrentStatus,"%0m/%d %H:%M")' | sort`;

    // Make a 2d array of the jobs on each platform
    $queue = Array();
    $queue_contents = split("\n", $output);
    foreach ($queue_contents as $line) {
      if(preg_match("/\s*(\S+)\s+(.+)$/", $line, $matches)) {
        if(!array_key_exists($matches[1], $queue)) {
          $queue[$matches[1]] = Array();
        }
        array_push($queue[$matches[1]], $matches[2]);
      }
    }

    // Run through each platform and parse the job information
    $formatted_queue = Array();
    foreach (array_keys($queue) as $platform) {
      $formatted_queue[$platform] = $this->parse_condor_q_output($platform, $queue[$platform]);
    }

    // Run through any platforms that didn't have jobs
    foreach ($this->platforms as $platform) {
      if(!array_key_exists($platform, $formatted_queue)) {
        $formatted_queue[$platform] = $this->parse_condor_q_output($platform, Array());
      }
    }

    return $formatted_queue;
  }

  function parse_condor_q_output($platform, $queue_contents) {
    // Parse the output and format it

    $depth = sizeof($queue_contents);
    $running_jobs = 0;

    $output = "";
    $slots = 0;
    
    if($this->pool) {
      if($this->pool[$platform]) {
	$output .= "<table>\n";
	$output .= "<tr><th>Host</th><th>Slots</th></tr>\n";
	foreach ($this->pool[$platform] as $host_count) {
	  $host = $host_count[0];
	  $num = $host_count[1];
	  $output .= "<tr><td>$host</td><td align='center'>$num</td></tr>\n";
	  $slots += $num;
	}
	$output .= "</table><br />\n";
      }
      else {
	$output .= "No slots available<br>\n";
      }
    }

    if($depth != 0) {
      $output .= "<table><tr><th>State</th><th>ID</th><th>Owner</th><th>Build</th><th>Test</th><th>Submitted</th><th>Started</th></tr>\n";
      foreach ($queue_contents as $line) {
        $items = preg_split("/\s+/", $line);
        if(sizeof($items) == 8) {
          $style = "background-color:#FFFFAA; text-decoration:none;";
          if($items[0] == "R") {
            $style = "background-color:#0097C5;";
            $running_jobs++;
          }
          else {
            // If the job is not running we don't care about 'EnteredCurrentStatus',
            // a.k.a. "Start Time"
            $items[6] = "";
            $items[7] = "";
            if($items[0] == "H") {
              $style = "background-color:#A1A1A1;";
            }
          }

	  $build = "&nbsp;";
	  $test = "&nbsp;";
	  if($items[3] == "build") {
	    $build = "B";
	  }
	  elseif($items[3] == "test") {
	    $test = "T";
	  }
	  
          $output .= "<tr style=\"$style\"><td>$items[0]</td><td>$items[1]</td><td>$items[2]</td><td>$build</td><td>$test</td><td>$items[4]&nbsp;$items[5]</td><td>$items[6]&nbsp;$items[7]</tr>\n";
        }
      }
      $output .= "</table>\n";
    }
    else {
      $output .= "<table><tr><th>State</th><th>ID</th><th>Owner</th><th>Submitted</th><th>Started</th></tr>\n";
      $output .= "<tr><td colspan=5>No jobs in queue</td></tr>";
      $output .= "</table>";
    }
        
    if($depth != 0 && $running_jobs == 0) {
      $output = "<font style=\"color:red\">* No job is running!</font><br />$output";
    }


    $ret = Array();
    $ret["depth"]      = $depth;
    $ret["running"]    = $running_jobs;
    $ret["slots"]      = $slots;
    $ret["html-queue"] = "<br /><span class=\"link\"><a href=\"javascript: void(0)\" style=\"text-decoration:none;\">Jobs: $depth<br>Running: $running_jobs<span>$output</span></a></span>";
    return $ret;
  }
}


?>