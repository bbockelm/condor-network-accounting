/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

/*
    This file implements the Reqexp class, which contains methods and
    data to manipulate the requirements expression of a given
    resource.

   	Written 9/29/97 by Derek Wright <wright@cs.wisc.edu>
*/

#include "condor_common.h"
#include "startd.h"

Reqexp::Reqexp( Resource* res_ip )
{
	this->rip = res_ip;
	MyString tmp;

	tmp.sprintf("%s = (%s) && (%s)", 
		ATTR_REQUIREMENTS, "START", ATTR_IS_VALID_CHECKPOINT_PLATFORM );

	if( Resource::STANDARD_SLOT != rip->get_feature() ) {
		tmp.sprintf_cat( " && (%s)", ATTR_WITHIN_RESOURCE_LIMITS );
	}

	origreqexp = strdup( tmp.Value() );
	origstart = NULL;
	rstate = ORIG_REQ;
	m_origvalidckptpltfrm = NULL;
	m_within_resource_limits_expr = NULL;
}

void
Reqexp::compute( amask_t how_much ) 
{
	MyString str;

	if( IS_STATIC(how_much) ) {
		char* start = param( "START" );
		if( !start ) {
			EXCEPT( "START expression not defined!" );
		}
		if( origstart ) {
			free( origstart );
		}

		str.sprintf( "%s = %s", ATTR_START, start );

		origstart = strdup( str.Value() );

		free( start );
	}

	if( IS_STATIC(how_much) ) {

		if (m_origvalidckptpltfrm != NULL) {
			free(m_origvalidckptpltfrm);
			m_origvalidckptpltfrm = NULL;
		}

		char *vcp = param( "IS_VALID_CHECKPOINT_PLATFORM" );
		if (vcp != NULL) {
			/* Use whatever the config file says */

			str.sprintf("%s = %s", ATTR_IS_VALID_CHECKPOINT_PLATFORM, vcp);

			m_origvalidckptpltfrm = strdup( str.Value() );

			free(vcp);

		} else {

			/* default to a simple policy of only resuming checkpoints
				which came from a machine like we are running on:
			
				Consider the checkpoint platforms to match IF
				0. If it is a non standard universe job (consider the "match"
					successful) OR
				1. If it is a standard universe AND
				2. There exists CheckpointPlatform in the machine ad AND
				3a.  the job's last checkpoint matches the machine's checkpoint 
					platform
				3b.  OR NumCkpts == 0

				Some assumptions I'm making are that 
				TARGET.LastCheckpointPlatform must NOT be present and is
				ignored if it is in the jobad when TARGET.NumCkpts is zero.

			*/
			const char *default_vcp_expr = 
			"("
			  "TARGET.JobUniverse =!= 1 || "
			  "("
			    "(MY.CheckpointPlatform =!= UNDEFINED) &&"
			    "("
			      "(TARGET.LastCheckpointPlatform =?= MY.CheckpointPlatform) ||"
			      "(TARGET.NumCkpts == 0)"
			    ")"
			  ")"
			")";
			
			str.sprintf( "%s = %s", ATTR_IS_VALID_CHECKPOINT_PLATFORM, 
				default_vcp_expr);

			m_origvalidckptpltfrm = strdup( str.Value() );
		}

		if( m_within_resource_limits_expr != NULL ) {
			free(m_within_resource_limits_expr);
			m_within_resource_limits_expr = NULL;
		}

		char *tmp = param( ATTR_WITHIN_RESOURCE_LIMITS );
		if( tmp != NULL ) {
			m_within_resource_limits_expr = strdup( tmp );
			free(tmp);
		} else {
			// In the below, _condor_RequestX attributes may be explicitly set by
			// the schedd; if they are not set, go with the RequestX that derived from
			// the user's original submission.
			tmp = const_cast<char*>(
				"("
				 "ifThenElse(TARGET._condor_RequestCpus =!= UNDEFINED,"
					"MY.Cpus > 0 && TARGET._condor_RequestCpus <= MY.Cpus,"
					"ifThenElse(TARGET.RequestCpus =!= UNDEFINED,"
						"MY.Cpus > 0 && TARGET.RequestCpus <= MY.Cpus,"
						"1 <= MY.Cpus))"
				" && "
				 "ifThenElse(TARGET._condor_RequestMemory =!= UNDEFINED,"
					"MY.Memory > 0 && TARGET._condor_RequestMemory <= MY.Memory,"
					"ifThenElse(TARGET.RequestMemory =!= UNDEFINED,"
						"MY.Memory > 0 && TARGET.RequestMemory <= MY.Memory,"
						"FALSE))"
				" && "
				 "ifThenElse(TARGET._condor_RequestDisk =!= UNDEFINED,"
					"MY.Disk > 0 && TARGET._condor_RequestDisk <= MY.Disk,"
					"ifThenElse(TARGET.RequestDisk =!= UNDEFINED,"
						"MY.Disk > 0 && TARGET.RequestDisk <= MY.Disk,"
						"FALSE))"
				")");
			m_within_resource_limits_expr = strdup( tmp );
		}
	}
}


Reqexp::~Reqexp()
{
	if( origreqexp ) free( origreqexp );
	if( origstart ) free( origstart );
	if( m_origvalidckptpltfrm ) free( m_origvalidckptpltfrm );
	if( m_within_resource_limits_expr ) free( m_within_resource_limits_expr );
}


bool
Reqexp::restore()
{
    if( rip->isSuspendedForCOD() ) {
		if( rstate != COD_REQ ) {
			rstate = COD_REQ;
			publish( rip->r_classad, A_PUBLIC );
			return true;
		} else {
			return false;
		}
	} else {
		rip->r_classad->Delete( ATTR_RUNNING_COD_JOB );
	}
	if( resmgr->isShuttingDown() || rip->isDraining() ) {
		if( rstate != UNAVAIL_REQ ) {
			unavail();
			return true;
		}
		return false;
	}
	if( rstate != ORIG_REQ) {
		rstate = ORIG_REQ;
		publish( rip->r_classad, A_PUBLIC );
		return true;
	}
	return false;
}


void
Reqexp::unavail() 
{
	if( rip->isSuspendedForCOD() ) {
		if( rstate != COD_REQ ) {
			rstate = COD_REQ;
			publish( rip->r_classad, A_PUBLIC );
		}
		return;
	}
	rstate = UNAVAIL_REQ;
	publish( rip->r_classad, A_PUBLIC );
}


void
Reqexp::publish( ClassAd* ca, amask_t /*how_much*/ /*UNUSED*/ )
{
	MyString tmp;

	switch( rstate ) {
	case ORIG_REQ:
		ca->Insert( origstart );
		tmp.sprintf( "%s", origreqexp );
		ca->Insert( tmp.Value() );
		tmp.sprintf( "%s", m_origvalidckptpltfrm );
		ca->Insert( tmp.Value() );
		if( Resource::STANDARD_SLOT != rip->get_feature() ) {
			ca->AssignExpr( ATTR_WITHIN_RESOURCE_LIMITS,
							m_within_resource_limits_expr );
		}
		break;
	case UNAVAIL_REQ:
		tmp.sprintf( "%s = False", ATTR_REQUIREMENTS );
		ca->Insert( tmp.Value() );
		break;
	case COD_REQ:
		tmp.sprintf( "%s = True", ATTR_RUNNING_COD_JOB );
		ca->Insert( tmp.Value() );
		tmp.sprintf( "%s = False && %s", ATTR_REQUIREMENTS,
				 ATTR_RUNNING_COD_JOB );
		ca->Insert( tmp.Value() );
		break;
	default:
		EXCEPT("Programmer error in Reqexp::publish()!");
		break;
	}
}


void
Reqexp::dprintf( int flags, char* fmt, ... )
{
	va_list args;
	va_start( args, fmt );
	rip->dprintf_va( flags, fmt, args );
	va_end( args );
}

