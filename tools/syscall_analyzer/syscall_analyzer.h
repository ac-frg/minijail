/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#if !defined(SYSCALL_ANALYZER_H_)
#define SYSCALL_ANALYZER_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "disassembler.h"

// A class that interacts with the Disassembler to create reports of used
// syscalls.
class SyscallAnalyzer {
 public:
  struct SyscallReport {
    std::set<int> direct_syscalls;
    std::set<BasicBlock*> called_functions;
  };

  // Factory method that creates a SyscallAnalyzer from the provided |filename|.
  static std::unique_ptr<SyscallAnalyzer> Create(
      std::unique_ptr<Disassembler> disassembler);

  // Gets the set of names of all symbols in the file.
  std::set<std::string> GetSymbolNames() const;

  // Gets the syscalls called by |function|.
  std::optional<std::set<int>> GetSyscallsTransitivelyCalledBy(
      std::string_view function_name);

  // Gets the syscalls called by |function|.
  std::optional<BasicBlock*> GetBasicBlock(std::string_view function_name);
  std::optional<SyscallReport> GetSyscallReportFor(BasicBlock* block);

 protected:
  SyscallAnalyzer(std::unique_ptr<Disassembler>);
  SyscallAnalyzer(const SyscallAnalyzer& o) = delete;
  SyscallAnalyzer& operator=(const SyscallAnalyzer& o) = delete;

  bool LoadSymbols();
  bool BuildControlFlowGraph();

  // Gets the syscalls called by |entry_point|.
  const SyscallReport& GetSyscallsCalledBy(BasicBlock* entry_point);

  uint64_t LookupTargetAddress(uint64_t target_address) const;

  // An owning list with all the symbol information from the binary.
  std::vector<std::unique_ptr<SymbolInfo>> symbols_;

  // Mappings between symbol names and addresses.
  std::map<uint64_t, SymbolInfo*> symbol_addresses_;
  std::multimap<std::string, SymbolInfo*> symbol_names_;

  // List of addresses of the syscall(3) function. May be multiple due to PLT
  // versions.
  std::set<uint64_t> syscall_addresses_;

  // The mapping of the set of syscalls that can be directly reachable from
  // each basic block, as well as any additional function it calls.
  std::map<const BasicBlock*, SyscallReport> syscall_report_map_;

  std::vector<std::unique_ptr<BasicBlock>> basic_blocks_;
  std::map<uint64_t, BasicBlock*> block_starts_;
  std::unique_ptr<Disassembler> disassembler_;
};

#endif  // SYSCALL_ANALYZER_H_
