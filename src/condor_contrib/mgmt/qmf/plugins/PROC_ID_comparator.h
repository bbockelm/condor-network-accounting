/*
 * Copyright 2009-2011 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _PROC_ID_COMPARATOR_H
#define _PROC_ID_COMPARATOR_H

#include <string>

struct PROC_ID_comparator
{
	bool operator()(const std::string &lhs, const std::string &rhs);
};

#endif /* _PROC_ID_COMPARATOR_H */
