/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file by using readelf to parse an unstripped dump_constants
// instead of executing it.

#include "parse_constants.h"

#include <iostream>
#include <memory>
#include <vector>

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace parse_constants {

using std::cerr;
using std::cout;
using std::endl;
using std::string;

namespace {

// Default app to launch, and evironment variable to override.
constexpr char kReadElf[] = "readelf";
constexpr char kReadElfEnvVar[] = "READELF";

// |segment_info| tracks how the base VA of a segment maps
// to a file offset and length in an ELF.
struct segment_info {
  unsigned long base_va;
  unsigned long file_offset;
  unsigned long file_length;
};

typedef std::vector<segment_info> segments;

// finds the VA and size for a symbol in an non-stripped ELF file.
bool parse_symbol_readelf(const string &file_name,
			  const string &symbol_name,
			  unsigned long long int &address,
			  unsigned long long int &size)
{
  char *readelf = getenv(kReadElfEnvVar);
  string command = string(readelf ? readelf : kReadElf);
  command += " --symbols --wide \"";
  command += file_name;
  command += "\" | grep -i ";
  command += symbol_name;

  string output;
  if (!run_command(command, output)) {
    return false;
  }

  const char *curr = output.c_str();
  while (*curr) {
    int number;
    unsigned long long int index;
    char curr_name[100];
    // example line of interest:
    // 33: 00008f98 13696 OBJECT  LOCAL  HIDDEN    22 constant_table
    int scanned = sscanf(curr, " %d: %llx %llu %*s %*s %*s %llu %99s",
			 &number, &address, &size, &index, curr_name);
    curr_name[sizeof(curr_name) - 1] = '\0';
    // Verify the name matches to avoid mistakenly using a different
    // variable with the same prefix as what we're looking for.
    if (scanned == 5 && symbol_name.compare(curr_name) == 0) {
      return true;
    }

    // advance to the next line
    ++curr;
    while (*curr && *(curr++) != '\n');
  }

  return false;
}

// Creates an array in |segments| where each element has the segment base VA,
// length and file offset in an non-stripped ELF file called |file_name|.
bool parse_segments_readelf(const string &file_name, segments &segments)
{
  char *readelf = getenv(kReadElfEnvVar);
  string command = readelf ? readelf : kReadElf;
  command += " --segments --wide \"";
  command += file_name;
  command += "\"";

  string output;
  if (!run_command(command, output)) {
    return false;
  }

  const char *curr = output.c_str();
  while (*curr) {
    unsigned long long int offset, va, pa, file_size, mem_size;
    // example line of interest:
    //  LOAD           0x0068d4 0x000078d4 0x000078d4 0x006bc 0x006bc R E 0x1000
    int scanned = sscanf(curr, " %*s %llx %llx %llx %llx %llx",
                         &offset, &va, &pa, &file_size, &mem_size);
    if (scanned == 5) {
      struct segment_info info = {va, offset, file_size};
      segments.push_back(info);
    }

    // advance to the next line
    ++curr;
    while (*curr && *(curr++) != '\n');
  }

  return true;
}

// converts a VA (e.g., from a symbol table) to an offset in an ELF file
unsigned long long int va_to_offset(const segments &segments,
				    unsigned long long int va)
{
  unsigned long long int best_offset = 0, best_va = 0;
  // Find the segment whose base address is closest to the va (but doesn't
  // come after the VA). We assume the segment is large enough to contain
  // the VA.
  for (segments::const_iterator i = segments.begin();
       i != segments.end(); ++i) {
    if (i->base_va <= va && i->base_va >= best_va) {
      best_va = i->base_va;
      best_offset = i->file_offset;
    }
  }
  return (va - best_va) + best_offset;
}

}  // namespace

// Parses an array called |table_name| of syscall_entry/constant_entry structs
// in an ELF file called |file_name|.  Results stored in |vector|.
bool parse_table_readelf(const string &file_name,
			 const string &table_name,
			 constant_vector &vector)
{
  // Obtain the VA and size of the table.
  unsigned long long int table_address = 0;
  unsigned long long int table_size = 0;
  if (!parse_symbol_readelf(file_name, table_name, table_address, table_size)) {
    cerr << "Failed to lookup " << table_name << endl;
    return false;
  }

  // Get the base VA and file offset of all the segments.
  segments segments;
  if (!parse_segments_readelf(file_name, segments)) {
    cerr << "Failed to parse segments in " << table_name << endl;
    return false;
  }

  // Map the elf file into memory.
  int fd = open(file_name.c_str(), O_RDONLY);
  if (fd < 0) {
    cerr << "Failed to open file " << file_name << endl;
    return false;
  }
  struct stat stats = {0};
  if (fstat(fd, &stats)) {
    cerr << "Failed to stat file: " << errno << endl;
    return false;
  }
  void *file_mem = mmap(nullptr, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (file_mem == (void *) -1) {
    cerr << "mmap failed: " << errno << endl;
    return false;
  }

  // Convert the array's VA into a file offset and parse the array.  Use
  // the ELF header to determine if we're dealing with 32-bit or 64-bit
  // pointers.
  char *start = ((char *)file_mem) + va_to_offset(segments, table_address);
  char *end = start + table_size;
  if (start < (char *)file_mem || end < start) {
    cerr << "Numeric overflow in address calculations" << endl;
    return false;
  }
  if (end > (char *)file_mem + stats.st_size) {
    cerr << "Array runs past the end of the file" << endl;
    return false;
  }
  bool use64 = stats.st_size > EI_CLASS &&
    ((unsigned char *)file_mem)[EI_CLASS] == ELFCLASS64;
  while (start < end) {
    size_t data_size = use64 ? sizeof(unsigned long) : sizeof(unsigned int);
    if (start + (data_size * 2) > end) {
      cerr << "Only portion of array element is present in file" << endl;
      return false;
    }
    unsigned long name_val = use64 ? *(unsigned long *)start :
      *(unsigned int *)start;
    start += data_size;
    unsigned long value = use64 ? *(unsigned long *)start :
      *(unsigned int *)start;
    start += data_size;
    if (name_val) {
      // Convert the name's VA into a file offset.
      char *name = ((char *)file_mem) + va_to_offset(segments, name_val);

      // This check doesn't catch the case where the string starts within
      // the file but isn't NULL terminated (i.e., runs past the end of
      // the file).
      if (name >= end) {
	cerr << "Name address is not within the file" << endl;
	return false;
      }
      constant_entry entry = {name, value};
      vector.push_back(entry);
    }
  }
  return true;
}

}  // namespace parse_constants
