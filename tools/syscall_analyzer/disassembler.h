/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#if !defined(DISASSEMBLER_H_)
#define DISASSEMBLER_H_

#include <iostream>
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
#include <llvm/MC/MCInst.h>
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

// The state of the processor. Contains the last-known values of all the
// registers and the topmost entry in the stack.
struct ProcessorState {
  std::map<uint32_t, std::optional<int64_t>> registers;
  std::optional<int64_t> top_stack;
};

std::ostream& operator<<(std::ostream& os, const ProcessorState& ps);

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
  // The state of the processor at the block exit.
  ProcessorState processor_state;
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

std::ostream& operator<<(std::ostream& os, const BasicBlock& bb);

struct ShortDescription {
  explicit ShortDescription(const BasicBlock* block);

  const BasicBlock* const block;
};

std::ostream& operator<<(std::ostream& os, const ShortDescription& sd);

// A wrapper around llvm::MCDisassembler.
class Disassembler {
 public:
  virtual ~Disassembler();

  // Initializes all LLVM objects.
  static void InitLLVM();

  virtual bool GetSymbols(
      std::vector<std::unique_ptr<SymbolInfo>>* out_symbols) = 0;
  virtual std::optional<std::pair<uint64_t, uint64_t>>
  GetExecutableSectionRangeContaining(uint64_t address);

  // Updates |processor_state| after interpreting |instruction|.
  void UpdateProcessorState(ProcessorState* processor_state,
                            const llvm::MCInst& instruction);

  // This is the syscall that holds the first argument into a function. Used to
  // figure out what the first argument to syscall(3) is.
  uint32_t first_arg_register = 0;

  // This is the register that holds the syscall number when invoking the
  // syscall software interrupt.
  uint32_t syscall_register = 0;

  // This is the "zero register" in aarch64, which always contains zero.
  uint32_t zero_register = 0;

  // This is the stack register.
  uint32_t stack_register = 0;

  // A mapping between register IDs and their largest super-register. Several
  // registers can share the same storage space, so changing one implicitly
  // changes the other. An example would be Intel's 64-bit %rax register, which
  // shares space with the 32-bit %eax, the 16-bit %ax, and the 8-bit %ah and
  // %al.
  //
  // This mapping is used to track the largest value of all physical registers.
  std::map<uint32_t, uint32_t> register_map;
  std::map<uint32_t, std::set<uint32_t>> register_clobber_map;

  // Objects used by LLVM that need to stay alive until we finish our analysis.
  llvm::Triple triple;
  std::unique_ptr<llvm::MemoryBuffer> memory_buffer;
  std::unique_ptr<const llvm::MCRegisterInfo> mri;
  std::unique_ptr<const llvm::MCAsmInfo> mai;
  std::unique_ptr<const llvm::MCInstrInfo> mii;
  std::unique_ptr<const llvm::MCInstrAnalysis> mia;
  std::unique_ptr<llvm::MCSubtargetInfo> sti;
  std::unique_ptr<llvm::MCObjectFileInfo> mofi;
  std::unique_ptr<llvm::MCContext> ctx;
  std::unique_ptr<const llvm::MCDisassembler> disassembler;

 protected:
  Disassembler();

  bool CreateLLVMObjectsForTriple(
      llvm::Triple triple,
      std::string_view subtarget_features = std::string_view());

 private:
  Disassembler(const Disassembler& o) = delete;
  Disassembler& operator=(const Disassembler& o) = delete;
};

// A disassembler that operates on an ELF file.
class ELFFileDisassembler : public Disassembler {
 public:
  // Opens an ELF file and loads it into memory.
  static std::unique_ptr<ELFFileDisassembler> OpenFile(
      std::string_view filename);

  ~ELFFileDisassembler() override;

  bool GetSymbols(
      std::vector<std::unique_ptr<SymbolInfo>>* out_symbols) override;
  std::optional<std::pair<uint64_t, uint64_t>>
  GetExecutableSectionRangeContaining(uint64_t address) override;

 private:
  ELFFileDisassembler();
  ELFFileDisassembler(const ELFFileDisassembler& o) = delete;
  ELFFileDisassembler& operator=(const ELFFileDisassembler& o) = delete;

  // The (sorted) list of all executable section ranges. Used to distinguish
  // between data and executable symbols.
  std::vector<std::pair<uint64_t, uint64_t>> executable_section_ranges_;

  std::unique_ptr<llvm::object::ELFObjectFileBase> obj_;
};

#endif  // DISASSEMBLER_H_
