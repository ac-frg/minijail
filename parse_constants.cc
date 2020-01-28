/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file by parsing an unstripped dump_constants
// instead of executing it.

#include "parse_constants.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using std::cerr;
using std::cout;
using std::endl;
using std::string;

namespace {

constexpr char kConstantTableName[] = "constant_table";
constexpr char kSyscallTableName[] = "syscall_table";
constexpr char kMinijailTableName[] = "minijail_arch";
constexpr char kMinijailArchNr[] = "MINIJAIL_ARCH_NR";
constexpr char kMinijailArchBits[] = "MINIJAIL_ARCH_BITS";

}  // namespace

namespace parse_constants {

// runs an app and returns stdout as a file.  Assumes app returns 0 for success.
bool run_command(const string &command, string &output)
{
  char output_file[] = "/tmp/appoutputXXXXXX";
  {
    int fd = mkstemp(output_file);
    if (fd < 0) {
      cerr << "Failed to derive temporary file name" << endl;
      return false;
    }
    close(fd);
  }

  string full_command = command + "> " + output_file;
  int result = system(full_command.c_str());
  if (result != 0) {
    cerr << "Failed to run \"" << full_command << "\": " << result << ' '
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

  if (unlink(output_file))
    cerr << "Failed to cleanup file " << output_file << endl;

  output = &buffer[0];

  return true;
}

namespace {

// Uses various approaches to try to parse a struct array (with
// name |table_name|) from a non-stripped ELF called |file_name|.
// Results are returned via |vector|.
bool parse_table(const string &file_name, const string &table_name,
		 constant_vector &constants)
{
  if (parse_table_readelf(file_name, table_name, constants)) {
    return true;
  }
  constants.empty();

  // First tries to parse without the helper length variable, but if
  // that fails then tries again using the helper variable.
  if (parse_table_gdb_mi(file_name, table_name, false, constants)) {
    return true;
  }
  constants.empty();
  if (parse_table_gdb_mi(file_name, table_name, true, constants)) {
    return true;
  }

  constants.empty();
  if (parse_table_gdb(file_name, table_name, false, constants)) {
    return true;
  }
  constants.empty();
  return parse_table_gdb(file_name, table_name, true, constants);
}

// Searches for element with specified name and provides its value.
// This is an inefficient linear search, but it's not intended for frequent use.
bool find(const constant_vector &constants, const string &name,
	  unsigned long long int &value) {
  for (parse_constants::constant_vector::const_iterator i = constants.begin();
       i != constants.end(); ++i) {
    if (i->name.compare(name) == 0) {
      value = i->value;
      return true;
    }
  }
  return false;
}

}  // namespace

}  // namespace parse_constants

int main(int argc, char *argv[]) {
  if (argc < 2) {
    cerr << "Path to 'dump_constants' is required\n";
    return 1;
  }
  if (access(argv[1], F_OK)) {
    cerr << "File does not exist: " << argv[1] << endl;
    return 1;
  }

  parse_constants::constant_vector constants;
  if (!parse_constants::parse_table(string(argv[1]),
				    string(kConstantTableName),
				    constants)) {
    cerr << "Failed to parse " << kConstantTableName << endl;
    return 1;
  }
  parse_constants::constant_vector syscalls;
  if (!parse_constants::parse_table(string(argv[1]),
				    string(kSyscallTableName),
				    syscalls)) {
    cerr << "Failed to parse " << kSyscallTableName << endl;
    return 1;
  }
  parse_constants::constant_vector arch;
  if (!parse_constants::parse_table(string(argv[1]),
				    string(kMinijailTableName),
				    arch) || arch.size() != 1) {
    cerr << "Failed to parse " << kMinijailTableName << endl;
    return 1;
  }

  unsigned long long int arch_nr = 0;
  unsigned long long int arch_bits = 0;
  if (!parse_constants::find(constants, string(kMinijailArchNr), arch_nr)) {

    cerr << "Failed to find architecture number" << endl;
    return 1;
  }
  if (!parse_constants::find(constants, string(kMinijailArchBits),
			     arch_bits)) {
    cerr << "Failed to find architecture bits" << endl;
    return 1;
  }

  cout << "{\n";
  cout << "  \"arch_nr\": " << arch_nr<< ",\n";
  cout << "  \"arch_name\": \"" << arch[0].name << "\",\n";
  cout << "  \"bits\": " << arch_bits << ",\n";
  cout << "  \"syscalls\": {\n";
  bool first = true;
  for (parse_constants::constant_vector::const_iterator i = syscalls.begin();
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
  for (parse_constants::constant_vector::const_iterator i = constants.begin();
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
