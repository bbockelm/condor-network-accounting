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


#include "condor_common.h"
#include "condor_debug.h"
#include "param_info.h"
#ifdef HAVE_PCRE_PCRE_H
#  include "pcre/pcre.h"
#else
#  include "pcre.h"
#endif

#define CUSTOMIZATION_SELDOM 	0

#define RECONFIG_NORMAL 		0

#define STATE_DEFAULT			0
#define STATE_AUTODEFAULT		1
#define STATE_USER				2
#define STATE_RUNTIME			3

//param_info_hash_t = bucket_t**
bucket_t** param_info;

#include "param_info_init.c"

const char*
param_default_string(const char* param)
{
	const param_info_t *p;
	const char* ret = NULL;

	param_info_init();
	p = param_info_hash_lookup(param_info, param);

	// Don't check the type here, since this is used in param and is used
	// to look up values for all types.
	if (p && p->default_valid) {
		ret = p->str_val;
	}

	return ret;
}

int
param_default_integer(const char* param, int* valid) {
	const param_info_t* p;
	int ret = 0;

	param_info_init();

	p = param_info_hash_lookup(param_info, param);

	if (p && (p->type == PARAM_TYPE_INT || p->type == PARAM_TYPE_BOOL)) {
        *valid = p->default_valid;
        if (*valid)
            ret = reinterpret_cast<const param_info_PARAM_TYPE_INT*>(p)->int_val;
	} else {
		*valid = 0;
	}

	return ret;
}

int
param_default_boolean(const char* param, int* valid) {
	return (param_default_integer(param, valid) != 0);
}

double
param_default_double(const char* param, int* valid) {


	const param_info_t* p;
	double ret = 0.0;

	param_info_init();

	p = param_info_hash_lookup(param_info, param);

	if (p && (p->type == PARAM_TYPE_DOUBLE)) {
		*valid = p->default_valid;
        if (*valid)
		    ret = reinterpret_cast<const param_info_PARAM_TYPE_DOUBLE*>(p)->dbl_val;
	} else {
		*valid = 0;
	}

	return ret;
}

int
param_range_integer(const char* param, int* min, int* max) {

	const param_info_t* p;

	p = param_info_hash_lookup(param_info, param);

	if (p) {
		if (p->type != PARAM_TYPE_INT) {
			return -1;
		}
        if ( ! p->range_valid) {
            *min = INT_MIN;
            *max = INT_MAX;
        } else {
		    *min = reinterpret_cast<const param_info_PARAM_TYPE_INT_ranged*>(p)->int_min;
		    *max = reinterpret_cast<const param_info_PARAM_TYPE_INT_ranged*>(p)->int_max;
        }
	} else {
		/* If the integer isn't known about, then don't assume a range for it */
/*		EXCEPT("integer range for param '%s' not found", param);*/
		return -1;
	}
	return 0;
}

int
param_range_double(const char* param, double* min, double* max) {

	const param_info_t* p;

	p = param_info_hash_lookup(param_info, param);

	if (p) {
		if(p->type != PARAM_TYPE_DOUBLE) {
			return -1;
		}
        if ( ! p->range_valid) {
            *min = DBL_MIN;
            *max = DBL_MAX;
        } else {
		    *min = reinterpret_cast<const param_info_PARAM_TYPE_DOUBLE_ranged*>(p)->dbl_min;
		    *max = reinterpret_cast<const param_info_PARAM_TYPE_DOUBLE_ranged*>(p)->dbl_max;
        }
	} else {
		/* If the double isn't known about, then don't assume a range for it */
/*		EXCEPT("double range for param '%s' not found", param);*/
		return -1;
	}
	return 0;
}

#if 0
/* XXX This function probably needs a lot of work. */
static void
compute_range(const char* range, char** range_start, char** range_end) {

	const char * c1 = NULL, * c2 = NULL, * c3 = NULL;

	for (c1=range; isspace(*c1); c1++);				//skip leading whitespace

	for (c2=c1; *c2 && *c2!=','; c2++);				//find the first comma or null terminator

	// if the same or they match the generalized anything operator, there is no range
	if (c1==c2 || (strcmp(c1, ".*") == 0)) {
		*range_start = (char *)malloc(sizeof(char));
		**range_start = '\0';
		*range_end = (char*)malloc(sizeof(char));
		**range_end = '\0';
	} else {

		//find range_start
		for (c3=c2-1; isspace(*c3); c3--);			//reverse over trailing whitespace
		*range_start = (char *)calloc((c3-c1+2), sizeof(char));
		strncat(*range_start, c1, c3-c1+1);

		//find range_end
		for (c1=c2; *c1; c1++);						//find end of uppper limit, stopping at null terminator
		for (c3=c1-1; isspace(*c3); c3--);			//reverse over trailing whitespace
		for (c2++; c2<=c1 && isspace(*c2); c2++);	//skip leading whitespace
		*range_end = (char *)calloc((c3-c2+2), sizeof(char));
		strncat(*range_end, c2, c3-c2+1);

	}
}

static int
validate_integer_range_lower_bound(const char* range_start, int* min) {

	char* end_ptr;
	int valid;

	if (*range_start) {
		*min = strtol(range_start,&end_ptr,10);
		//if it's an empty string, it's not valid
		if (end_ptr != range_start) {
			//if rest of string is anything but whitespace it's not valid
			for ( ; isspace(*end_ptr); end_ptr++);
			valid = (*end_ptr == '\0');
		} else {
			valid = 0;
		}
	} else {
		valid = 0;
	}

	if (!valid) {
		//if not valid assume no bound
		*min = INT_MIN;
	}

	return valid;
}

static int
validate_integer_range_upper_bound(const char* range_end, int* max) {

	char* end_ptr;
	int valid;

	if (*range_end) {
		*max = strtol(range_end,&end_ptr,10);
		//if it's an empty string, it's not valid
		if (end_ptr != range_end) {
			//if rest of string is anything but whitespace it's not valid
			for ( ; isspace(*end_ptr); end_ptr++);
			valid = (*end_ptr == '\0');
		} else {
			valid = 0;
		}
	} else {
		valid = 0;
	}

	if (!valid) {
		//if not valid assume no bound
		*max = INT_MAX;
	}

	return valid;
}

static int
validate_double_range_lower_bound(const char* range_start, double* min) {

	char* end_ptr;
	int valid;

	if (*range_start) {
		*min = strtol(range_start,&end_ptr,10);
		//if it's an empty string, it's not valid
		if (end_ptr != range_start) {
			//if rest of string is anything but whitespace it's not valid
			for ( ; isspace(*end_ptr); end_ptr++);
			valid = (*end_ptr == '\0');
		} else {
			valid = 0;
		}
	} else {
		valid = 0;
	}

	if (!valid) {
		//if not valid assume no bound
		*min = DBL_MIN;
	}

	return valid;
}

static int
validate_double_range_upper_bound(const char* range_end, double* max) {

	char* end_ptr;
	int valid;

	if (*range_end) {
		*max = strtod(range_end,&end_ptr);
		//if it's an empty string, it's not valid
		if (end_ptr != range_end) {
			//if rest of string is anything but whitespace it's not valid
			for ( ; isspace(*end_ptr); end_ptr++);
			valid = (*end_ptr == '\0');
		} else {
			valid = 0;
		}
	} else {
		valid = 0;
	}

	if (!valid) {
		//if not valid assume no bound
		*max = DBL_MAX;
	}

	return valid;
}

static int
validate_regex(const char* pattern, const char* subject) {

	pcre* re;
	const char* err;
	int err_index;
    int group_count;
	int oveccount;
	int* ovector;
	int matches;
	int i;
	int is_valid = 0;
	int subject_len;

	//compile the regex with default options
	re = pcre_compile(pattern, 0, &err, &err_index, NULL);

	//figure out how many groups there are so we can size ovector appropriately
	pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &group_count);
	oveccount = 2 * (group_count + 1); // +1 for the string itself
	ovector = (int *)malloc(oveccount * sizeof(int));

	if (!ovector) {
		EXCEPT("unable to allocated memory for regex group info in validate_regex");
	}

	subject_len = strlen(subject);

	//run the regex
	matches = pcre_exec(re, NULL, subject, subject_len, 0, 0, ovector, oveccount);

	//make sure that one of the matches is the whole string
	for (i=0; i<matches; i++) {
		if (ovector[i*2] == 0 && ovector[i*2+1] == subject_len) {
			is_valid = 1;
			break;
		}
	}

	free(ovector);

	pcre_free(re);

	return is_valid;
}
#endif

void
iterate_params(int (*callPerElement)
				(const param_info_t* /*value*/, void* /*user data*/),
				void* user_data) {
	param_info_hash_iterate(param_info, callPerElement, user_data);
}

