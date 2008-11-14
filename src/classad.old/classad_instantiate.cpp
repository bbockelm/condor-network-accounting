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
#include "condor_classad.h"
#include "ad_printmask.h"
#include "ListCache.h"
#include "YourString.h"
#include "HashTable.h"

template class List<Formatter>;
template class Item<Formatter>;
template class ListCache<ClassAd>;
template class ListCacheEntry<ClassAd>;
template class List<ListCacheEntry<ClassAd> >;
template class Item<ListCacheEntry<ClassAd> >;
template class ListIterator<ListCacheEntry<ClassAd> >;
template class List<ExprTree>;
template class Item<ExprTree>;
template class ListIterator<ExprTree>;
template class HashTable<YourString, AttrListElem *>;