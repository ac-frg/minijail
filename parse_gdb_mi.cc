/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file by using gdb (in MI mode) to parse an unstripped
// dump_constants instead of executing it.

#include "parse_constants.h"

#include <climits>
#include <cstring>
#include <iostream>

namespace parse_constants {

using std::cerr;
using std::cout;
using std::endl;
using std::string;

namespace {

// parse files of the form:
//
// 100^done
// 200^done
// 300^done
// 400^done,value="{{name = \"read\", nr = 0}, {name = , nr = -1}}"
// 500^exit
//
// Another variation of the fourth line is:
//
// 400^done,value="{{name = \"x86_64\", value = 64}}"
//
// For either form the second struct member may be called |nr|
// (used by libsyscalls.h) or |value| (used by libsyscalls.h).
//
// The first line might be prefixed with other unrelated lines (e.g.,
// start up logging or the result of a print command that's used by
// parse_table_gdb_mi() when |query_length| is true).

// The first part of the array line
constexpr char kArrayPrefix[] = "400^done,value=\"{";
constexpr size_t kArrayPrefixLen = (sizeof(kArrayPrefix) - 1);

// The first part of each element
constexpr char kNamePrefix[] = "{name = ";
constexpr size_t kNamePrefixLen = (sizeof(kNamePrefix) - 1);

// The second part of each element
constexpr char kNameSuffix[] = ", value = ";
constexpr size_t kNameSuffixLen = (sizeof(kNameSuffix) - 1);
constexpr char kNameSuffix2[] = ", nr = ";
constexpr size_t kNameSuffix2Len = (sizeof(kNameSuffix2) - 1);

// Status responses from gdb
constexpr char kDoneString[] = "^done\n";
constexpr size_t kDoneStringLen = (sizeof(kDoneString) - 1);
constexpr char kExitString[] = "^exit\n";
constexpr size_t kExitStringLen = (sizeof(kExitString) - 1);

// Default app to launch, and evironment variable to override.
constexpr char kGdb[] = "gdb";
constexpr char kGdbEnvVar[] = "GDB";

// Parses a string line looking for #^done (or #^exit if |exit| is true),
// where the # is the expected value specified by the caller via |number|.
// Updates |curr| to point to the first character that comes after the line.
bool verify_okay(unsigned int number, const char *&line, bool exit = false)
{
  char *end = nullptr;
  const char *curr = line;
  unsigned long value = strtoul(curr, &end, 0);
  if (value != number) {
    return false;
  }
  curr = end;

  if (exit) {
    if (strncmp(curr, kExitString, kExitStringLen)) {
      return false;
    }
    curr += kExitStringLen;
  } else {
    if (strncmp(curr, kDoneString, kDoneStringLen)) {
      return false;
    }
    curr += kDoneStringLen;
  }

  line = curr;
  return true;
}

}  // namespace

// parse_table_gdb_mi() tries to use gdb (gdb to use is optionally specified by
// the "GDB" environment variable) to query and parse an array called
// |table_name| from an executable file called |file_name|. Some symbols lack
// the array length, so if |query_length| is true then function will also
// attempt to use a variable with name |table_name| (plus a "_len" suffix) that
// indicates the number of elements in the array. The contents of the array is
// added to |vector|.
bool parse_table_gdb_mi(const string &file_name, const string &table_name,
			bool query_length, constant_vector &vector)
{
  char *gdb = getenv(kGdbEnvVar);
  // Assemble the command-line. The gdb docs suggest we should pass
  // "--interpreter=mi2" but this doesn't seem to affect the interpreter that
  // is used to evalute commands passed via --eval-command.  A workaround is to
  // specify a "interpreter-exec mi2" prefix to each command passed to
  // --eval-command.
  // For the |query_length| workaround (when it's set to true), we need to query
  // the array length and then specify the length when calling
  // data-evaluate-expression. I couldn't find a pure-mi2 way to run the length
  // query and have it set state (i.e., a variable) that could be referenced to
  // print the array contents.  Rather than use gdb interactively, or run it
  // twice (once to get the length, and again to print the array), I've opted
  // to run "print" using the conventional interpreter (which by default sets
  // $1 to the value of the request) and then reference $1 when calling
  // data-evaluate-expression.  The main movation for mi2 is to try to
  // mitigate the chance of the array parsing code breaking due to future
  // changes in gdb, so for now this seems like a decent tradeoff.
  string command = gdb ? gdb : kGdb;
  command += " \"";
  command += file_name;
  command += "\" --nx --nw --silent --batch ";
  if (query_length) {
    command += "'--eval-command=print ";
    command += table_name;
    command += "_len' ";
  }
  // The number 100, 200, 300, and 400 are arbitrary -- they're intended to help
  // an app match up replies with commands.
  command += "'--eval-command=interpreter-exec mi2 "
             "\"100-gdb-set pagination off\"' ";
  command += "'--eval-command=interpreter-exec mi2 "
             "\"200-gdb-set print elements unlimited\"' ";
  command += "'--eval-command=interpreter-exec mi2 "
             "\"300-gdb-set print address off\"' ";
  command += "'--eval-command=interpreter-exec mi2 "
             "\"400-data-evaluate-expression ";
  if (query_length)
    command += "*";
  command += table_name;
  if (query_length)
    command += "@\\$1";
  command += "\"' ";
  command += "'--eval-command=interpreter-exec mi2 "
             "\"500-gdb-exit\"' 2> /dev/null";

  string output;
  if (!run_command(command, output)) {
    return false;
  }

  const char *curr = output.c_str();

  // Skip any intro lines until we see a line for the first MI command.
  while (curr && !verify_okay(100, curr)) {
    curr = strchr(curr, '\n');
    if (curr) {
      ++curr;
    }
  }

  if (!curr) {
    cerr << "Did not find a response for command 1" << endl;
    return false;
  }
  if (!verify_okay(200, curr)) {
    cerr << "Unexpected response to command 2" << endl;
    return false;
  }
  if (!verify_okay(300, curr)) {
    cerr << "Unexpected response to command 3" << endl;
    return false;
  }

  if (strncmp(curr, kArrayPrefix, kArrayPrefixLen)) {
    // If |query_length| is false then we'll try again with it set to
    // true.  So, don't complain unless it's true.
    if (query_length)
      cerr << "Variable value has unexpected start" << endl;
    return false;
  }
  curr += kArrayPrefixLen;

  while (curr[0]) {
    if (strncmp(curr, kNamePrefix, kNamePrefixLen)) {
      cerr << "Element has unexpected start" << endl;
      return false;
    }
    curr += kNamePrefixLen;

    string name;

    if (curr[0] == ',') {
      // No name exists to parse
    } else if (curr[0] != '\\' || curr[1] != '\"') {
      cerr << "Character after 'name' wasn't comma or quote" << endl;
      return false;
    } else {
      curr += 2;

      // Scan the string looking for the closing \" (without getting
      // fooled by other escape characters, though these generally
      // shouldn't exist since we're parsing C constant/variable names).
      const char *name_end = strchr(curr, '\\');
      while (name_end && name_end[1] != '\"') {
	if (!name_end[1]) {
	  name_end = nullptr;
	  break;
	}
	name_end += 2;
	name_end = strchr(name_end, '\\');
      }
      if (!name_end) {
	cerr << "Failed to find end of name" << endl;
	return false;
      }
      name = string(curr, name_end-curr);
      curr = name_end + 2;
    }

    if (strncmp(curr, kNameSuffix, kNameSuffixLen) == 0)
      curr += kNameSuffixLen;
    else if (strncmp(curr, kNameSuffix2, kNameSuffix2Len) == 0)
      curr += kNameSuffix2Len;
    else {
      cerr << "Name has unexpected suffix" << endl;
      return false;
    }

    char *value_end = nullptr;
    errno = 0;
    unsigned long long int value = strtoull(curr, &value_end, 0);
    if ((value == 0 && errno == EINVAL) ||
	(value == ULLONG_MAX && errno == ERANGE)) {
      cerr << "Failed to parse value" << endl;
      return false;
    }
    if (!value_end || value_end[0] != '}') {
      cerr << "Value has unexpected suffix" << endl;
      return false;
    }
    curr = value_end + 1;

    if (name.length() > 0) {
      constant_entry entry = {name, value};
      vector.push_back(entry);
    }

    if (curr[0] == ',' && curr[1] == ' ')
      curr += 2;
    else if (curr[0] == '}') {
      // saw final closure
      ++curr;
      if (curr[0] != '"') {
	cerr << "array didn't end with quote" << endl;
	return false;
      }
      ++curr;
      break;
    } else {
      cerr << "Unexpected start to next element" << endl;
      return false;
    }
  }

  if (!verify_okay(500, curr, true)) {
    cerr << "Unexpected response to command 5" << endl;
    return false;
  }

  return true;
}

}  // namespace parse_constants
