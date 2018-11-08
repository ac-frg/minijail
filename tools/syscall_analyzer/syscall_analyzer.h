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

// A wrapper around llvm::MCDisassembler.
class SyscallAnalyzer {
 public:
  // Initializes all LLVM objects.
  static void InitLLVM();

  // Factory method that creates a SyscallAnalyzer from the provided |filename|.
  static std::unique_ptr<SyscallAnalyzer> OpenFile(std::string_view filename);

  // Gets the set of names of all symbols in the file.
  std::set<std::string> GetSymbolNames() const;

  // Gets the syscalls called by |function|.
  std::optional<std::set<int>> GetSyscallsCalledBy(std::string_view function);

 private:
  SyscallAnalyzer() = default;
  SyscallAnalyzer(const SyscallAnalyzer& o) = delete;
  SyscallAnalyzer& operator=(const SyscallAnalyzer& o) = delete;

  // Loads the file into memory, as well as all the LLVM machinery needed to
  // analyze it.
  bool LoadFile(std::string_view filename);

  // Gets the syscalls called by |entry_point|.
  const std::set<int>& GetSyscallsCalledBy(BasicBlock* entry_point);

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
  std::vector<std::unique_ptr<SymbolInfo>> symbols_;
  std::vector<std::pair<uint64_t, uint64_t>> executable_section_ranges_;
  std::map<uint32_t, uint32_t> register_map_;
  std::map<BasicBlock*, std::set<int>> syscall_map_;
};

#endif  // SYSCALL_ANALYZER_H_
