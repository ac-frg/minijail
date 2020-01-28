/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file by parsing an unstripped dump_constants
// instead of executing it.

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

namespace {

using std::cerr;
using std::endl;

constexpr char kConstantTableName[] = "constant_table";
constexpr char kSyscallTableName[] = "syscall_table";
constexpr char kMinijailTableName[] = "minijail_arch";
constexpr char kMinijailArchNr[] = "MINIJAIL_ARCH_NR";
constexpr char kMinijailArchBits[] = "MINIJAIL_ARCH_BITS";

// |constant_entry| maps a |name| to a |value|.  It's desirable to maintain
// order and duplicates so |vector| is used rather than a form of map.
struct constant_entry {
  std::string name;
  uint64_t value;
};
typedef std::vector<constant_entry> constant_vector;

// |segment_info| tracks how the base VA of a segment maps
// to a file offset in an ELF.
struct segment_info {
  uint64_t base_va;
  uint64_t file_offset;
};
typedef std::vector<segment_info> segments;

// Converts a virtual address (VA) to an offset in an ELF file.
uint64_t va_to_offset(const segments &segments, uint64_t va) {
  uint64_t best_offset = 0, best_va = 0;
  // Find the segment whose base address is closest to the VA (but doesn't
  // come after the VA). We assume the segment is large enough to contain
  // the VA.
  for (segments::const_iterator i = segments.begin(); i != segments.end();
       ++i) {
    if (i->base_va <= va && i->base_va >= best_va) {
      best_va = i->base_va;
      best_offset = i->file_offset;
    }
  }
  return (va - best_va) + best_offset;
}

// |unmapper| is used to garbage collect a file mapping.
class unmapper {
 public:
  unmapper(void *m = nullptr, size_t l = 0) : _mapping(m), _length(l) {}
  unmapper(const unmapper &) = delete;
  unmapper(unmapper &&) = delete;
  unmapper &operator=(const unmapper &) = delete;
  unmapper &operator=(unmapper &&o) {
    this->~unmapper();
    _mapping = o._mapping;
    _length = o._length;
    o._mapping = nullptr;
    o._length = 0;
    return *this;
  }
  ~unmapper() {
    if (_mapping) {
      munmap(_mapping, _length);
    }
  }

 private:
  void *_mapping;
  size_t _length;
};

// Parses an array called |table_name| of syscall_entry/constant_entry structs
// in an ELF file called |file_name|.  Results stored in |vector|.
bool parse_table(const std::string &file_name, const std::string &table_name,
                 constant_vector &vector) {
  void *file_mem = nullptr;
  uint64_t file_size = 0;
  unmapper unmap;
  // Map the elf file into memory.
  {
    int fd = open(file_name.c_str(), O_RDONLY);
    if (fd < 0) {
      cerr << "Failed to open file " << file_name << endl;
      return false;
    }
    struct stat stats = {0};
    if (fstat(fd, &stats)) {
      cerr << "Failed to stat file: " << errno << endl;
      close(fd);
      return false;
    }
    file_size = stats.st_size;
    file_mem = mmap(nullptr, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_mem == (void *)-1) {
      cerr << "mmap failed: " << errno << endl;
      close(fd);
      return false;
    }
    close(fd);
    unmap = std::move(unmapper(file_mem, stats.st_size));
  }

  // Check if elf is for 32-bit or 64-bit and verify endian.
  if (file_size <= EI_DATA) {
    cerr << "File size too short for ELF header: " << file_size << endl;
    return false;
  }
  bool elf64 = false;
  {
    uint8_t elf_class = reinterpret_cast<uint8_t *>(file_mem)[EI_CLASS];
    if (elf_class != ELFCLASS32 && elf_class != ELFCLASS64) {
      cerr << "Elf class is unknown: " << elf_class << endl;
      return false;
    }
    elf64 = elf_class == ELFCLASS64;

    uint8_t elf_data = reinterpret_cast<uint8_t *>(file_mem)[EI_DATA];
    if (elf_data != ELFDATA2LSB) {
      cerr << "Elf data endian not supported: " << elf_data << endl;
      return false;
    }
  }

  // Determine the location and size of the section list. Store the list
  // in |segments| and record the offset and size of the string and symbol
  // segments.
  if (file_size < (elf64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr))) {
    cerr << "File size too short for entire ELF header: " << file_size << endl;
    return false;
  }
  segments segments;
  uint64_t strings_offset = 0, strings_size = 0;
  uint64_t symbol_segment_offset = 0, symbol_segment_size = 0;
  {
    uint64_t section_header = 0;
    uint16_t section_entry_size = 0;
    uint16_t section_entry_count = 0;
    uint16_t section_names_index = 0;
    if (!elf64) {
      Elf32_Ehdr *header = reinterpret_cast<Elf32_Ehdr *>(file_mem);
      section_header = header->e_shoff;
      section_entry_size = header->e_shentsize;
      section_entry_count = header->e_shnum;
      section_names_index = header->e_shstrndx;
    } else {
      Elf64_Ehdr *header = reinterpret_cast<Elf64_Ehdr *>(file_mem);
      section_header = header->e_shoff;
      section_entry_size = header->e_shentsize;
      section_entry_count = header->e_shnum;
      section_names_index = header->e_shstrndx;
    }

    if (section_header + section_entry_size * section_entry_count <
        section_header) {
      cerr << "Numeric overflow while verifying segment attributes" << endl;
      return false;
    }
    if (section_header + section_entry_size * section_entry_count > file_size) {
      cerr << "File size " << file_size << " is too small to contain "
           << section_entry_count << " segment entries of size "
           << section_entry_size << endl;
      return false;
    }
    if (section_entry_size <
        (elf64 ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr))) {
      cerr << "Section entry size " << section_entry_size
           << " is smaller than expected" << endl;
      return false;
    }

    uint8_t *curr = reinterpret_cast<uint8_t *>(file_mem) + section_header;
    for (uint32_t i = 0; i < section_entry_count; ++i) {
      uint32_t type = 0;
      uint64_t va = 0, offset = 0, size = 0;
      if (!elf64) {
        Elf32_Shdr *section = reinterpret_cast<Elf32_Shdr *>(curr);
        type = section->sh_type;
        va = section->sh_addr;
        offset = section->sh_offset;
        size = section->sh_size;
      } else {
        Elf64_Shdr *section = reinterpret_cast<Elf64_Shdr *>(curr);
        type = section->sh_type;
        va = section->sh_addr;
        offset = section->sh_offset;
        size = section->sh_size;
      }
      segment_info info = {va, offset};
      segments.push_back(info);
      if (type == SHT_SYMTAB) {
        if (symbol_segment_size) {
          cerr << "Saw multiple symbol segments" << endl;
          return false;
        }
        symbol_segment_offset = offset;
        symbol_segment_size = size;
      }
      // There's typically two string sections -- one for regular strings and
      // another for section names.  We'll ignore the latter.
      if (type == SHT_STRTAB && i != section_names_index) {
        if (strings_size) {
          cerr << "Saw multiple strings segments" << endl;
          return false;
        }
        strings_offset = offset;
        strings_size = size;
      }
      curr += section_entry_size;
    }
  }
  if (!strings_size) {
    cerr << "Failed to find string table" << endl;
    return false;
  }
  if (!symbol_segment_size) {
    cerr << "Failed to find symbol segment" << endl;
    return false;
  }
  if (strings_offset + strings_size < strings_offset ||
      symbol_segment_offset + symbol_segment_size < symbol_segment_offset) {
    cerr << "Numeric overflow in string and/or symbol segment offset/size"
         << endl;
    return false;
  }
  if (strings_offset + strings_size > file_size) {
    cerr << "Entire string segment isn't contained within file" << endl;
    return false;
  }
  if (symbol_segment_offset + symbol_segment_size > file_size) {
    cerr << "Entire symbol segment isn't contained within file" << endl;
    return false;
  }

  // Search for the address and size of the |table_name| symbol and
  // store in |table_address| and |table_size|.
  uint64_t table_address = 0;
  uint64_t table_size = 0;
  {
    uint8_t *sym_curr =
        reinterpret_cast<uint8_t *>(file_mem) + symbol_segment_offset;
    uint8_t *sym_end = sym_curr + symbol_segment_size;
    while (sym_curr < sym_end) {
      uint32_t sym_name = 0;
      uint64_t sym_addr = 0;
      uint64_t sym_size = 0;
      if (!elf64) {
        Elf32_Sym *sym = reinterpret_cast<Elf32_Sym *>(sym_curr);
        sym_name = sym->st_name;
        sym_addr = sym->st_value;
        sym_size = sym->st_size;
        sym_curr += sizeof(Elf32_Sym);
      } else {
        Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(sym_curr);
        sym_name = sym->st_name;
        sym_addr = sym->st_value;
        sym_size = sym->st_size;
        sym_curr += sizeof(Elf64_Sym);
      }
      // This check doesn't catch the case where |sym_name| isn't zero
      // terminated or extends beyond the end of the strings segment.
      if (sym_name >= strings_size) {
        cerr << "Symbol name " << sym_name << " is outside strings segment "
             << strings_size << endl;
        return false;
      }
      if (table_name.compare(reinterpret_cast<char *>(file_mem) +
                             strings_offset + sym_name) == 0) {
        table_address = sym_addr;
        table_size = sym_size;
        break;
      }
    }
  }
  if (!table_address || !table_size) {
    cerr << "Failed to find " << table_name << endl;
    return false;
  }

  // Convert the array's VA into a file offset and parse the array.
  uint8_t *start = reinterpret_cast<uint8_t *>(file_mem) +
                   va_to_offset(segments, table_address);
  uint8_t *end = start + table_size;
  if (start < reinterpret_cast<uint8_t *>(file_mem) || end < start) {
    cerr << "Numeric overflow in address calculations" << endl;
    return false;
  }
  if (end > reinterpret_cast<uint8_t *>(file_mem) + file_size) {
    cerr << "Array runs past the end of the file" << endl;
    return false;
  }
  while (start < end) {
    size_t data_size = elf64 ? sizeof(uint64_t) : sizeof(uint32_t);
    if (start + (data_size * 2) > end) {
      cerr << "Only portion of array element is present in file" << endl;
      return false;
    }
    uint64_t name_val = elf64 ? *reinterpret_cast<uint64_t *>(start)
                              : *reinterpret_cast<uint32_t *>(start);
    start += data_size;
    uint64_t value = elf64 ? *reinterpret_cast<uint64_t *>(start)
                           : *reinterpret_cast<uint32_t *>(start);
    start += data_size;
    if (name_val) {
      // Convert the name's VA into a file offset.
      uint64_t name_offset = va_to_offset(segments, name_val);
      // This check doesn't catch the case where the string starts within
      // the file but isn't zero terminated (i.e., runs past the end of
      // the file).
      if (name_offset >= file_size) {
        cerr << "Name address is not within the file" << endl;
        return false;
      }
      constant_entry entry = {reinterpret_cast<char *>(file_mem) + name_offset,
                              value};
      vector.push_back(entry);
    }
  }
  return true;
}

// Searches for element with specified name and provides its value.
// This is an inefficient linear search, but it's not intended for frequent use.
bool find_constant(const constant_vector &constants, const std::string &name,
                   uint64_t &value) {
  for (constant_vector::const_iterator i = constants.begin();
       i != constants.end(); ++i) {
    if (i->name.compare(name) == 0) {
      value = i->value;
      return true;
    }
  }
  return false;
}

}  // namespace

int main(int argc, char *argv[]) {
  if (argc < 2) {
    cerr << "Path to 'dump_constants' is required\n";
    return 1;
  }
  if (access(argv[1], F_OK)) {
    cerr << "File does not exist: " << argv[1] << endl;
    return 1;
  }

  constant_vector constants;
  if (!parse_table(std::string(argv[1]), std::string(kConstantTableName),
                   constants)) {
    cerr << "Failed to parse " << kConstantTableName << endl;
    return 1;
  }
  constant_vector syscalls;
  if (!parse_table(std::string(argv[1]), std::string(kSyscallTableName),
                   syscalls)) {
    cerr << "Failed to parse " << kSyscallTableName << endl;
    return 1;
  }
  constant_vector arch;
  if (!parse_table(std::string(argv[1]), std::string(kMinijailTableName),
                   arch) ||
      arch.size() != 1) {
    cerr << "Failed to parse " << kMinijailTableName << endl;
    return 1;
  }

  uint64_t arch_nr = 0;
  uint64_t arch_bits = 0;
  if (!find_constant(constants, std::string(kMinijailArchNr), arch_nr)) {
    cerr << "Failed to find architecture number" << endl;
    return 1;
  }
  if (!find_constant(constants, std::string(kMinijailArchBits), arch_bits)) {
    cerr << "Failed to find architecture bits" << endl;
    return 1;
  }

  std::cout << "{\n";
  std::cout << "  \"arch_nr\": " << arch_nr << ",\n";
  std::cout << "  \"arch_name\": \"" << arch[0].name << "\",\n";
  std::cout << "  \"bits\": " << arch_bits << ",\n";
  std::cout << "  \"syscalls\": {\n";

  bool first = true;
  for (constant_vector::const_iterator i = syscalls.begin();
       i != syscalls.end(); ++i) {
    if (first)
      first = false;
    else
      std::cout << ",\n";
    std::cout << "    \"" << i->name << "\": " << uint32_t(i->value);
  }
  std::cout << "\n  },\n";
  std::cout << "  \"constants\": {\n";
  first = true;
  for (constant_vector::const_iterator i = constants.begin();
       i != constants.end(); ++i) {
    if (first)
      first = false;
    else
      std::cout << ",\n";
    std::cout << "    \"" << i->name << "\": " << i->value;
  }
  std::cout << "\n  }\n";
  std::cout << "}\n";

  return 0;
}
