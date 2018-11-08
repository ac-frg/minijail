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

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>

struct BasicBlock;

// The name and address span of a symbol in the binary.
struct SymbolInfo {
  uint64_t start;
  uint64_t end;
  std::string name;
  BasicBlock* entry_point = nullptr;

  SymbolInfo(uint64_t start, uint64_t end, std::string_view name);

  bool operator<(const SymbolInfo& o) const;
};

// A contiguous sequence of instructions with no control flow changes (i.e.
// jumps, method calls, returns), except maybe at the end.
//
// This forms the nodes of the Control Flow Graph.
struct BasicBlock {
  uint64_t start;
  uint64_t end;
  std::vector<std::pair<uint64_t, llvm::MCInst>> instructions{};
  SymbolInfo* symbol = nullptr;
  std::set<BasicBlock*> out_edges;
  std::set<BasicBlock*> in_edges;
  // The set of registers-values at the block exit.
  std::map<uint32_t, std::optional<int64_t>> registers;
  bool ends_with_call_to_syscall = false;
  bool is_entry_point = false;

  BasicBlock(uint64_t start, uint64_t end);

  bool operator<(const BasicBlock& o) const;

  // Splits the current BasicBlock at |address|. This can happen if we discover
  // an in-edge after building the block.
  std::unique_ptr<BasicBlock> SplitAt(uint64_t address);

  // Visits the subgraph that starts in the current node in reverse postorder.
  // This is then useful to run some dataflow analysis passes.
  std::vector<BasicBlock*> ReversePostorder();

 private:
  void ReversePostorderImpl(std::vector<BasicBlock*>* out_blocks,
                            std::set<BasicBlock*>* visited);
};

struct ShortDescription {
  explicit ShortDescription(const BasicBlock* block);

  const BasicBlock* const block;
};

std::ostream& operator<<(std::ostream& os, const ShortDescription& sd);

// A wrapper around llvm::MCDisassembler.
class SyscallAnalyzer {
 public:
  struct SyscallReport {
    std::set<int> direct_syscalls;
    std::set<BasicBlock*> called_functions;
  };

  // Initializes all LLVM objects.
  static void InitLLVM();

  // Factory method that creates a SyscallAnalyzer from the provided |filename|.
  static std::unique_ptr<SyscallAnalyzer> OpenFile(std::string_view filename);

  // Gets the set of names of all symbols in the file.
  std::set<std::string> GetSymbolNames() const;

  // Gets the syscalls called by |function|.
  std::optional<std::set<int>> GetSyscallsTransitivelyCalledBy(
      std::string_view function_name);

  // Gets the syscalls called by |function|.
  std::optional<BasicBlock*> GetBasicBlock(std::string_view function_name);
  std::optional<SyscallReport> GetSyscallReportFor(BasicBlock* block);

 private:
  SyscallAnalyzer() = default;
  SyscallAnalyzer(const SyscallAnalyzer& o) = delete;
  SyscallAnalyzer& operator=(const SyscallAnalyzer& o) = delete;

  // Loads the file into memory, as well as all the LLVM machinery needed to
  // analyze it.
  bool LoadFile(std::string_view filename);

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

  // The (sorted) list of all executable section ranges. Used to distinguish
  // between data and executable symbols.
  std::vector<std::pair<uint64_t, uint64_t>> executable_section_ranges_;

  // A mapping between register IDs and their largest super-register. Several
  // registers can share the same storage space, so changing one implicitly
  // changes the other. An example would be Intel's 64-bit %rax register, which
  // shares space with the 32-bit %eax, the 16-bit %ax, and the 8-bit %ah and
  // %al.
  //
  // This mapping is used to track the largest value of all physical registers.
  std::map<uint32_t, uint32_t> register_map_;
  std::map<uint32_t, std::set<uint32_t>> register_clobber_map_;

  // The mapping of the set of syscalls that can be directly reachable from
  // each basic block, as well as any additional function it calls.
  std::map<BasicBlock*, SyscallReport> syscall_report_map_;

  // This is the syscall that holds the first argument into a function. Used to
  // figure out what the first argument to syscall(3) is.
  uint32_t first_arg_register_ = 0;

  // This is the register that holds the syscall number when invoking the
  // syscall software interrupt.
  uint32_t syscall_register_ = 0;

  std::vector<std::unique_ptr<BasicBlock>> basic_blocks_;
  std::map<uint64_t, BasicBlock*> block_starts_;

  // Objects used by LLVM that need to stay alive until we finish our analysis.
  std::unique_ptr<llvm::object::ELFObjectFileBase> obj_;
  std::unique_ptr<llvm::MemoryBuffer> memory_buffer_;
  std::unique_ptr<const llvm::MCRegisterInfo> mri_;
  std::unique_ptr<const llvm::MCAsmInfo> mai_;
  std::unique_ptr<const llvm::MCInstrInfo> mii_;
  std::unique_ptr<const llvm::MCInstrAnalysis> mia_;
  std::unique_ptr<llvm::MCSubtargetInfo> sti_;
  std::unique_ptr<llvm::MCObjectFileInfo> mofi_;
  std::unique_ptr<llvm::MCContext> ctx_;
  std::unique_ptr<const llvm::MCDisassembler> disassembler_;
};

#endif  // SYSCALL_ANALYZER_H_
