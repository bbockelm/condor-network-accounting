/***************************************************************
 *
 * Copyright (C) 1990-2010, Condor Team, Computer Sciences Department,
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

#ifndef _stl_string_utils_h_
#define _stl_string_utils_h_ 1

#include <string>
#include <vector>
#include <sstream>
#include "condor_header_features.h"
#include "MyString.h"

// sprintf() will try to write to a fixed buffer first, for reasons of 
// efficiency.  This is the size of that buffer.
#define STL_STRING_UTILS_FIXBUF 500

// Analogous to standard sprintf(), but writes to std::string 's', and is
// memory/buffer safe.
int sprintf(std::string& s, const char* format, ...) CHECK_PRINTF_FORMAT(2,3);
int sprintf(MyString& s, const char* format, ...) CHECK_PRINTF_FORMAT(2,3);

// Appending versions of above.
// These return number of new chars appended.
int sprintf_cat(std::string& s, const char* format, ...) CHECK_PRINTF_FORMAT(2,3);
int sprintf_cat(MyString& s, const char* format, ...) CHECK_PRINTF_FORMAT(2,3);

// comparison ops between the two houses divided
bool operator==(const MyString& L, const std::string& R);
bool operator==(const std::string& L, const MyString& R);
bool operator!=(const MyString& L, const std::string& R);
bool operator!=(const std::string& L, const MyString& R);
bool operator<(const MyString& L, const std::string& R);
bool operator<(const std::string& L, const MyString& R);
bool operator>(const MyString& L, const std::string& R);
bool operator>(const std::string& L, const MyString& R);
bool operator<=(const MyString& L, const std::string& R);
bool operator<=(const std::string& L, const MyString& R);
bool operator>=(const MyString& L, const std::string& R);
bool operator>=(const std::string& L, const MyString& R);

// MyString now provides casting ops that make these unnecessary.
// Can now use '=' between MyString <--> std::string
// The below assignment std::string <-- MyString will be more 
// efficient, due to some copying in the casting op, if that matters.
void assign(std::string& dst, const MyString& src);
void assign(MyString& dst, const std::string& src);

bool chomp(std::string &str);
void trim(std::string &str);
void lower_case(std::string &str);
void upper_case(std::string &str);

void Tokenize(const MyString &str);
void Tokenize(const std::string &str);
void Tokenize(const char *str);
const char *GetNextToken(const char *delim, bool skipBlankTokens);

void join(std::vector< std::string > &v, char const *delim, std::string &result);

// Returns true iff (s) casts to <T>, and all of (s) is consumed,
// i.e. if (s) is an exact representation of a value of <T>, no more and
// no less.
template<typename T>
bool lex_cast(const std::string& s, T& v) {
    std::stringstream ss(s);
    ss >> v;
    return ss.eof() && (0 == (ss.rdstate() & std::stringstream::failbit));
}

#endif // _stl_string_utils_h_
