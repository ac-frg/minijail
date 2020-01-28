/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file with all the architecture-specific constants.

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

#include "arch.h"
#include "libconstants.h"
#include "libsyscalls.h"

// The arch name and bits is stored in an |constant_entry| array to
// facilitate parsing by parse_constants.cc. If the name of either
// variable is changed then parse_constants.cc will need an update.
// The |minijail_arch_len| helps that file to determine the array length.
constant_entry minijail_arch[1] = {{MINIJAIL_ARCH_NAME, MINIJAIL_ARCH_BITS}};
size_t minijail_arch_len = sizeof(minijail_arch)/sizeof(minijail_arch[0]);

int main() {
  std::cout << "{\n";
  std::cout << "  \"arch_nr\": " << MINIJAIL_ARCH_NR << ",\n";
  std::cout << "  \"arch_name\": \"" << minijail_arch[0].name << "\",\n";
  std::cout << "  \"bits\": " << minijail_arch[0].value << ",\n";
  std::cout << "  \"syscalls\": {\n";
  bool first = true;
  for (const struct syscall_entry* entry = syscall_table; entry->name;
       ++entry) {
    if (first)
      first = false;
    else
      std::cout << ",\n";
    std::cout << "    \"" << entry->name << "\": " << entry->nr;
  }
  std::cout << "\n  },\n";
  std::cout << "  \"constants\": {\n";
  first = true;
  for (const struct constant_entry* entry = constant_table; entry->name;
       ++entry) {
    if (first)
      first = false;
    else
      std::cout << ",\n";
    std::cout << "    \"" << entry->name << "\": " << entry->value;
  }
  std::cout << "\n  }\n";
  std::cout << "}\n";

  return 0;
}
