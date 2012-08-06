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
#include "param_info.h"

static unsigned int
param_info_hash(const char *str)
{
	unsigned int hash = 5381;
	unsigned char c;

	while ((c = toupper(*str++)) != 0) {
		hash = (hash * 33) + c;
	}

	return hash % PARAM_INFO_TABLE_SIZE;
}

void
param_info_hash_insert(param_info_hash_t param_info, param_info_storage_t const *p) {

	unsigned int key;
	bucket_t* b;

	key = param_info_hash(p->type_string.hdr.name);

	if (!param_info[key]) {

		param_info[key] = (bucket_t *)malloc(sizeof(bucket_t));
		param_info_storage_t * param = &(param_info[key]->param);
		*param = *p;
		param_info[key]->next = NULL;

	} else {

		b = param_info[key];
		while(b->next) {
			b = b->next;
		}
		b->next = (bucket_t *)malloc(sizeof(bucket_t));
		if (b->next) {
			b = b->next;
			param_info_storage_t *param = &b->param;
			*param = *p;
			b->next = NULL;
		}
	}
}

const param_info_t*
param_info_hash_lookup(param_info_hash_t param_info, const char* param) {

	unsigned int key;
	bucket_t* b;

	key = param_info_hash(param);

	b = param_info[key];
	while(b != NULL) {
		if (strcasecmp(b->param.type_string.hdr.name,param) == 0) {
			return &(b->param.type_string.hdr);
		}
		b = b->next;
	}

	return NULL;
}

// of type to be used by param_info_hash_iterate
int
param_info_hash_dump_value(const param_info_t* param_value, void* /*unused*/ ) {
	printf("%s:  default=", param_value->name);
#if 1
    if ( ! param_value->default_valid)
       printf("<Undefined>");
    else
	switch (param_value->type) {
		case PARAM_TYPE_STRING:
			printf("%s", reinterpret_cast<const param_info_PARAM_TYPE_STRING*>(param_value)->hdr.str_val);
			break;
		case PARAM_TYPE_DOUBLE:
			printf("%f", reinterpret_cast<const param_info_PARAM_TYPE_DOUBLE*>(param_value)->dbl_val);
			break;
		case PARAM_TYPE_INT:
			printf("%d", reinterpret_cast<const param_info_PARAM_TYPE_INT*>(param_value)->int_val);
			break;
		case PARAM_TYPE_BOOL:
			printf("%s", reinterpret_cast<const param_info_PARAM_TYPE_BOOL*>(param_value)->int_val == 0 ? "false" : "true");
			break;
	}
#else
	switch (param_value->type) {
		case PARAM_TYPE_STRING:
			printf("%s", param_value->default_val.str_val);
			break;
		case PARAM_TYPE_DOUBLE:
			printf("%f", param_value->default_val.dbl_val);
			break;
		case PARAM_TYPE_INT:
			printf("%d", param_value->default_val.int_val);
			break;
		case PARAM_TYPE_BOOL:
			printf("%s", param_value->default_val.int_val == 0 ? "false" : "true");
			break;
	}
#endif
	printf("\n");
	return 0;
}

void
param_info_hash_dump(param_info_hash_t param_info) {
	param_info_hash_iterate(param_info, &param_info_hash_dump_value, NULL);
}

void
param_info_hash_iterate(param_info_hash_t param_info, int (*callPerElement)
			(const param_info_t* /*value*/, void* /*user data*/), void* user_data) {
	int i;
	int stop = 0;
	for(i = 0; i < PARAM_INFO_TABLE_SIZE && stop == 0; i++) {
		bucket_t* this_param = (bucket_t*)(param_info + i);
		while(this_param != NULL && stop == 0) {
			stop = callPerElement(&(this_param->param.type_string.hdr), user_data);
			this_param = this_param->next;
		}
	}
}

// Iterate through the hash table and re-allocate memory in chunks.
void
param_info_hash_optimize(param_info_hash_t param_info)
{
    // As of July 2012, the occupancy rate of the hash was about 90%.
    int i;
    int bucket_count = 0;
    for(i = 0; i < PARAM_INFO_TABLE_SIZE; i++)
    {
        bucket_t* this_param = param_info[i];
        while(this_param != NULL)
        {
            bucket_count++;
            this_param = this_param->next;
        }
    }
    bucket_t * buckets = (bucket_t*)malloc(sizeof(bucket_t)*bucket_count);
    int bucket_offset = 0;
    for(i = 0; i < PARAM_INFO_TABLE_SIZE; i++)
    {
        bucket_t* this_param = param_info[i];
        if (this_param != NULL)
        {
            param_info[i] = buckets + bucket_offset;
        }
        while(this_param != NULL)
        {
           buckets[bucket_offset] = *this_param;
           bucket_t* old_param = this_param;
           this_param = this_param->next;
           if (this_param)
           {
               buckets[bucket_offset].next = &buckets[bucket_offset+1];
           } else {
               buckets[bucket_offset].next = NULL;
           }
           free(old_param);
           bucket_offset++;
        }
    }
}

void 
param_info_hash_create(param_info_hash_t* param_info) {
	*param_info = (bucket_t **)malloc(sizeof(bucket_t*)*PARAM_INFO_TABLE_SIZE);
	memset(*param_info,0,sizeof(bucket_t*)*PARAM_INFO_TABLE_SIZE);
}

