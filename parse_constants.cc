/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file by parsing an unstripped dump_constants
// instead of executing it.

#include <climits>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <stdlib.h>
#include <unistd.h>

using std::cerr;
using std::cout;
using std::endl;
using std::string;

struct constant_entry {
  string name;
  unsigned long long int value;
};

typedef std::vector<constant_entry> constant_vector;

#define CONSTANT_TABLE_NAME "constant_table"
#define SYSCALL_TABLE_NAME "syscall_table"
#define MINIJAIL_TABLE_NAME "minijail_arch"
#define MINIJAIL_ARCH_NR "MINIJAIL_ARCH_NR"
#define MINIJAIL_ARCH_BITS "MINIJAIL_ARCH_BITS"

// parse files of the form:
//
// $1 = 160
// $2 = {{name = "exit", nr = 1}, {name = "fork", nr = 2}, {name = , nr = -1}}
//
// or
//
// $1 = {{name = "exit", nr = 1}, {name = "fork", nr = 2}, {name = , nr = -1}}
//
// or
//
// $1 = {{name = "x86_64", value = 64}}
//
// The first form is when gdb doesn't know the length of the array and
// we must ask it to 'print' the length variable.  The latter is when
// the length variable has been optimized away but gdb knows the array length.
// The third form is used to handle a single-element array that reports
// the arch information.  The second struct member may be called |nr| (used
// by libsyscalls.h) or |value| (used by libsyscalls.h).

// The first part of the array line
#define FILE_PREFIX "$1 = {"
#define FILE_PREFIX_LEN (sizeof(FILE_PREFIX) - 1)
// The first part of each element
#define NAME_PREFIX "{name = "
// The second part of each element
#define NAME_PREFIX_LEN (sizeof(NAME_PREFIX) - 1)
#define NAME_SUFFIX ", value = "
#define NAME_SUFFIX_LEN (sizeof(NAME_SUFFIX) - 1)
#define NAME_SUFFIX2 ", nr = "
#define NAME_SUFFIX2_LEN (sizeof(NAME_SUFFIX2) - 1)

// parse_table() tries to use gdb (gdb to use is optionally specified by the
// "GDB" environment variable) to query and parse an array called
// |table_name| from an executable file called |file_name|. If |query_length|
// is true then function will also attempt to use a variable with name
// |table_name| (plus a "_len" suffix) that indicates the number of elements
// in the array.  The contents of the array is added to |vector|.
static bool parse_table(const string &file_name, const string &table_name,
			bool query_length, constant_vector &vector)
{
  char output_file[] = "/tmp/gdboutXXXXXX";
  char *gdb = getenv("GDB");
  {
    int fd = mkstemp(output_file);
    if (fd < 0) {
      cerr << "Failed to derive temporary file name" << endl;
      return false;
    }
    close(fd);
  }
  string command = gdb ? gdb : "gdb";
  command += " \"";
  command += file_name;
  command += "\" --nx --silent --batch \"--eval-command=set pagination off\" ";
  if (query_length) {
    command += "\"--eval-command=print ";
    command += table_name;
    command += "_len\" ";
  }
  command += "\"--eval-command=set print elements unlimited\" ";
  command += "\"--eval-command=set print address off\" ";
  command += "\"--eval-command=print ";
  if (query_length)
    command += "*";
  command += table_name;
  if (query_length)
    command += "@\\$1";
  command += "\" \"--eval-command=quit\" 2> /dev/null > \"";
  command += output_file;
  command += "\"";
  int result = system(command.c_str());
  if (result != 0) {
    cerr << "Failed to run \"" << command << "\": " << result << ' '
	 << errno << endl;
    return false;
  }
  std::ifstream input(output_file);
  if (input.fail()) {
    cerr << "Failed to open file: " << output_file << endl;
    return false;
  }

  // Get the length of the file.
  input.seekg(0, input.end);
  size_t length = input.tellg();
  input.seekg(0, input.beg);

  // Length padded by 1 so array is nul-terminated.
  std::unique_ptr<char[]> buffer(new char[length + 1]);
  input.read(&buffer[0], length);
  if (input.fail() || (size_t)input.gcount() != length) {
    cerr << "Failed to read from file: " << output_file << endl;
    return false;
  }
  input.close();
  buffer[length] = '\0';

  char *curr = &buffer[0];

  if (query_length)
    // We don't care about the reported length (it's merely passed as $1 to
    // the next command) so skip over the first line.
    while (*curr && *(curr++) != '\n');

  // Convert $2 to $1 to simplify the comparision that follows.
  if (curr[0] == '$' && curr[1] == '2')
    curr[1] = '1';

  if (strncmp(curr, FILE_PREFIX, FILE_PREFIX_LEN)) {
    // If |query_length| is false then we'll try again with it set to
    // true.  So, don't complain unless it's true, and if it's false
    // then cleanup the file.
    if (query_length)
      cerr << "File " << output_file << " has unexpected start" << endl;
    else
      unlink(output_file);
    return false;
  }
  curr += FILE_PREFIX_LEN;

  while (curr[0]) {
    if (strncmp(curr, NAME_PREFIX, NAME_PREFIX_LEN)) {
      cerr << "Element has unexpected start in " << output_file << endl;
      return false;
    }
    curr += NAME_PREFIX_LEN;

    if (curr[0] == ',')
      // no name specified, so stop parsing
      break;
    else if (curr[0] != '\"') {
      cerr << "Character after 'name' wasn't comma or quote in "
	   << output_file << endl;
      return false;
    }
    ++curr;

    char *end = strchr(curr, '\"');
    if (!end) {
      cerr << "Failed to find end of name in " << output_file << endl;
      return false;
    }
    string name(curr, end-curr);
    curr = end + 1;
    if (strncmp(curr, NAME_SUFFIX, NAME_SUFFIX_LEN) == 0)
      curr += NAME_SUFFIX_LEN;
    else if (strncmp(curr, NAME_SUFFIX2, NAME_SUFFIX2_LEN) == 0)
      curr += NAME_SUFFIX2_LEN;
    else {
      cerr << "Name has unexpected suffix in " << output_file << endl;
      return false;
    }

    end = nullptr;
    errno = 0;
    unsigned long long int value = strtoull(curr, &end, 0);
    if ((value == 0 && errno == EINVAL) ||
	(value == ULLONG_MAX && errno == ERANGE)) {
      cerr << "Failed to parse value in " << output_file << endl;
      return false;
    }
    if (!end || end[0] != '}') {
      cerr << "Value has unexpected suffix in " << output_file << endl;
      return false;
    }
    curr = end + 1;
    constant_entry entry = {name, value};
    vector.push_back(entry);

    if (curr[0] == ',' && curr[1] == ' ')
      curr += 2;
    else if (curr[0] == '}')
      // saw final closure
      break;
    else {
      cerr << "Unexpected start to next element in " << output_file << endl;
      return false;
    }
  }

  // File is left behind on error paths to facilitate debugging.
  if (unlink(output_file))
    cerr << "Failed to cleanup file " << output_file << endl;

  return true;
}

// First tries to parse without the helper length variable, but if
// that fails then tries again using the helper variable.
static bool parse_table(const string &file_name, const string &table_name,
			constant_vector &vector)
{
  if (parse_table(file_name, table_name, false, vector))
    return true;
  return parse_table(file_name, table_name, true, vector);
}

// Searches for element with specified name and provides its value
static bool find(const constant_vector &vector, const string &name,
		 unsigned long long int &value) {
  for (size_t i = 0; i < vector.size(); ++i)
    if (vector[i].name.compare(name) == 0) {
      value = vector[i].value;
      return true;
    }

  cerr << "Failed to find element " << name << endl;
  return false;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    cerr << "Path to dump_constants is required\n";
    return 1;
  }
  if (access(argv[1], F_OK)) {
    cerr << "File does not exist: " << argv[1] << endl;
    return 1;
  }

  constant_vector constants;
  if (!parse_table(string(argv[1]), string(CONSTANT_TABLE_NAME),
		   constants)) {
    cerr << "Failed to parse " << CONSTANT_TABLE_NAME << endl;
    return 1;
  }
  constant_vector syscalls;
  if (!parse_table(string(argv[1]), string(SYSCALL_TABLE_NAME),
		   syscalls)) {
    cerr << "Failed to parse " << SYSCALL_TABLE_NAME << endl;
    return 1;
  }
  constant_vector arch;
  if (!parse_table(string(argv[1]), string(MINIJAIL_TABLE_NAME),
		   false, arch) || arch.size() != 1) {
    cerr << "Failed to parse " << MINIJAIL_TABLE_NAME << endl;
    return 1;
  }

  unsigned long long int arch_nr = 0;
  unsigned long long int arch_bits = 0;
  if (!find(constants, string(MINIJAIL_ARCH_NR), arch_nr)) {
    return 1;
  }
  if (!find(constants, string(MINIJAIL_ARCH_BITS), arch_bits)) {
    return 1;
  }

  cout << "{\n";
  cout << "  \"arch_nr\": " << arch_nr<< ",\n";
  cout << "  \"arch_name\": \"" << arch[0].name << "\",\n";
  cout << "  \"bits\": " << arch_bits << ",\n";
  cout << "  \"syscalls\": {\n";
  bool first = true;
  for (constant_vector::const_iterator i = syscalls.begin();
       i != syscalls.end(); ++i) {
    if (first)
      first = false;
    else
      cout << ",\n";
    cout << "    \"" << i->name << "\": " << (int)i->value;
  }
  cout << "\n  },\n";
  cout << "  \"constants\": {\n";
  first = true;
  for (constant_vector::const_iterator i = constants.begin();
       i != constants.end(); ++i) {
    if (first)
      first = false;
    else
      cout << ",\n";
    cout << "    \"" << i->name << "\": " << (unsigned long)i->value;
  }
  cout << "\n  }\n";
  cout << "}\n";

  return 0;
}
