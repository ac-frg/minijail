/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "syscall_analyzer.h"

#include <algorithm>
#include <limits>
#include <queue>

#include <llvm/MC/MCInst.h>
#include <llvm/Object/Archive.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_os_ostream.h>

#include "logging.h"

namespace {

// A helper class that facilitates printing the state of the registers of a
// BasicBlock, as opposed to information about the block itself.
struct RegisterState {
  explicit RegisterState(const BasicBlock& block) : block(&block) {}
  explicit RegisterState(BasicBlock* block) : block(block) {}
  explicit RegisterState(const BasicBlock* block) : block(block) {}

  const BasicBlock* const block;
};

std::ostream& operator<<(std::ostream& os, const RegisterState& rs) {
  os << "Registers{";
  for (const auto it : rs.block->registers) {
    os << " reg[" << std::dec << it.first << "] = ";
    if (it.second == std::nullopt)
      os << "<clobbered>";
    else
      os << std::hex << it.second.value();
  }
  return os << " }";
}

struct PrintInstruction {
  PrintInstruction(const llvm::MCInst& instruction,
                   const llvm::MCInstrInfo* mii)
      : instruction(instruction), mii(mii) {}

  const llvm::MCInst& instruction;
  const llvm::MCInstrInfo* const mii;
};

std::ostream& operator<<(std::ostream& os, const PrintInstruction& pi) {
  const std::string mnemonic = pi.mii->getName(pi.instruction.getOpcode());
  auto& instruction_desc = pi.mii->get(pi.instruction.getOpcode());
  std::string buf;
  {
    llvm::raw_string_ostream os(buf);
    pi.instruction.dump_pretty(os);
  }
  os << mnemonic << " " << buf << " [defs=" << std::dec
     << instruction_desc.getNumDefs() << ", flags=" << std::hex
     << instruction_desc.getFlags();
  if (instruction_desc.isVariadic())
    os << ", variadic";
  if (instruction_desc.hasOptionalDef())
    os << ", optional_def";
  if (instruction_desc.isPseudo())
    os << ", pseudo";
  if (instruction_desc.isReturn())
    os << ", return";
  if (instruction_desc.isAdd())
    os << ", add";
  if (instruction_desc.isCall())
    os << ", call";
  if (instruction_desc.isBarrier())
    os << ", barrier";
  if (instruction_desc.isIndirectBranch())
    os << ", indirect_branch";
  if (instruction_desc.isBranch())
    os << ", branch";
  if (instruction_desc.isUnconditionalBranch())
    os << ", unconditional_branch";
  if (instruction_desc.isPredicable())
    os << ", predicable";
  if (instruction_desc.isCompare())
    os << ", compare";
  if (instruction_desc.isMoveImmediate())
    os << ", move_immediate";
  if (instruction_desc.isMoveReg())
    os << ", move_reg";
  if (instruction_desc.isBitcast())
    os << ", bitcast";
  if (instruction_desc.isSelect())
    os << ", select";
  if (instruction_desc.isNotDuplicable())
    os << ", not_duplicable";
  if (instruction_desc.hasDelaySlot())
    os << ", has_delay_slot";
  if (instruction_desc.hasUnmodeledSideEffects())
    os << ", has_unmodeled_side_effects";
  if (instruction_desc.isCommutable())
    os << ", commutable";
  if (instruction_desc.isConvertibleTo3Addr())
    os << ", convertible_to_3addr";

  os << "]";
  return os;
}

std::ostream& operator<<(std::ostream& os, const std::set<int>& syscalls) {
  os << "syscalls[" << std::dec;
  for (int syscall_nr : syscalls)
    os << " " << syscall_nr;
  return os << " ]";
}

}  // namespace

SymbolInfo::SymbolInfo(uint64_t start, uint64_t end, std::string_view name)
    : start(start), end(end), name(name) {}

bool SymbolInfo::operator<(const SymbolInfo& o) const {
  if (start == o.start)
    return end < o.end;
  return start < o.start;
}

BasicBlock::BasicBlock(uint64_t start, uint64_t end) : start(start), end(end) {}

bool BasicBlock::operator<(const BasicBlock& o) const {
  if (start == o.start)
    return end < o.end;
  return start < o.start;
}

std::ostream& operator<<(std::ostream& os, const BasicBlock& block) {
  os << "Block{";
  if (block.symbol)
    os << " symbol: " << block.symbol->name;
  os << " address: (" << std::hex << block.start << ", " << block.end
     << "), parents: {";
  for (const auto* parent : block.in_edges)
    os << " (" << parent->start << ", " << parent->end << ")";
  os << " }, children: {";
  for (const auto* child : block.out_edges)
    os << " (" << child->start << ", " << child->end << ")";
  if (block.ends_with_call_to_syscall)
    os << " ends with call to syscall";
  os << " }";
  return os;
}

std::unique_ptr<BasicBlock> BasicBlock::SplitAt(uint64_t address) {
  LOG(DEBUG) << "Splitting block " << *this << " at " << std::hex << address;
  auto previous = std::make_unique<BasicBlock>(start, address);
  start = address;

  // Migrate all of the instructions that now belong to the previous block.
  auto it = instructions.begin();
  for (; it != instructions.end() && it->first < address; ++it)
    previous->instructions.emplace_back(it->first, std::move(it->second));
  instructions.erase(instructions.begin(), it);

  // Migrate all of this block's edges to the previous block.
  for (auto* parent : in_edges) {
    parent->out_edges.erase(this);
    parent->out_edges.insert(previous.get());
    previous->in_edges.insert(parent);
  }

  // And finally establish an edge between the previous and current blocks.
  in_edges.clear();
  previous->out_edges.insert(this);
  in_edges.insert(previous.get());
  if (is_entry_point) {
    is_entry_point = false;
    previous->is_entry_point = true;
  }

  return previous;
}

std::vector<BasicBlock*> BasicBlock::ReversePostorder() {
  std::vector<BasicBlock*> result;
  std::set<BasicBlock*> visited;
  ReversePostorderImpl(&result, &visited);
  std::reverse(result.begin(), result.end());
  return result;
}

void BasicBlock::ReversePostorderImpl(std::vector<BasicBlock*>* out_blocks,
                                      std::set<BasicBlock*>* visited) {
  if (visited->find(this) != visited->end())
    return;
  visited->insert(this);
  for (auto* next : out_edges) {
    if (next->symbol != symbol)
      continue;
    next->ReversePostorderImpl(out_blocks, visited);
  }
  out_blocks->emplace_back(this);
}

ShortDescription::ShortDescription(const BasicBlock* block) : block(block) {}

std::ostream& operator<<(std::ostream& os, const ShortDescription& sd) {
  if (sd.block->symbol)
    os << sd.block->symbol->name;
  else
    os << "0x" << std::hex << sd.block->start;
  return os;
}

// static
std::unique_ptr<SyscallAnalyzer> SyscallAnalyzer::Create(
    std::unique_ptr<Disassembler> disassembler) {
  if (!disassembler)
    return nullptr;
  std::unique_ptr<SyscallAnalyzer> syscall_analyzer(
      new SyscallAnalyzer(std::move(disassembler)));
  if (!syscall_analyzer->LoadSymbols())
    return nullptr;
  if (!syscall_analyzer->BuildControlFlowGraph())
    return nullptr;
  return syscall_analyzer;
}

std::set<std::string> SyscallAnalyzer::GetSymbolNames() const {
  std::set<std::string> symbols;
  // Skip the synthetic symbols.
  for (const auto& symbol_info : symbols_) {
    if (symbol_info->name.find("@plt") != std::string::npos)
      continue;
    symbols.insert(symbol_info->name);
  }
  return symbols;
}

std::optional<std::set<int>> SyscallAnalyzer::GetSyscallsTransitivelyCalledBy(
    std::string_view function) {
  SymbolInfo* symbol = nullptr;
  for (const auto& symbol_info : symbols_) {
    if (symbol_info->name == function) {
      symbol = symbol_info.get();
      break;
    }
  }
  if (!symbol)
    return std::nullopt;

  std::set<BasicBlock*> visited;
  std::queue<BasicBlock*> q({symbol->entry_point});
  std::set<int> called_syscalls;
  while (!q.empty()) {
    BasicBlock* block = q.front();
    q.pop();

    if (!visited.insert(block).second)
      continue;
    auto report = GetSyscallsCalledBy(block);
    called_syscalls.insert(report.direct_syscalls.begin(),
                           report.direct_syscalls.end());
    for (BasicBlock* child : report.called_functions)
      q.push(child);
  }
  return std::make_optional(std::move(called_syscalls));
}

std::optional<BasicBlock*> SyscallAnalyzer::GetBasicBlock(
    std::string_view function_name) {
  SymbolInfo* symbol = nullptr;
  for (const auto& symbol_info : symbols_) {
    if (symbol_info->name == function_name) {
      symbol = symbol_info.get();
      break;
    }
  }
  if (!symbol || !symbol->entry_point)
    return std::nullopt;

  return std::make_optional<BasicBlock*>(symbol->entry_point);
}

SyscallAnalyzer::SyscallAnalyzer(std::unique_ptr<Disassembler> disassembler)
    : disassembler_(std::move(disassembler)) {}

std::optional<SyscallAnalyzer::SyscallReport>
SyscallAnalyzer::GetSyscallReportFor(BasicBlock* block) {
  if (!block)
    return std::nullopt;
  return std::make_optional<SyscallReport>(GetSyscallsCalledBy(block));
}

bool SyscallAnalyzer::LoadSymbols() {
  if (!disassembler_->GetSymbols(&symbols_))
    return false;

  for (auto& symbol : symbols_) {
    symbol_addresses_.emplace(symbol->start, symbol.get());
    symbol_names_.emplace(symbol->name, symbol.get());
  }

  // syscall(3) is a special function that we want to keep track of, since
  // it's the way the vast majority of userspace code interacts directly with
  // the syscall interface.
  for (const auto* syscall_name : {"syscall", "syscall@plt"}) {
    auto range = symbol_names_.equal_range(syscall_name);
    for (auto it = range.first; it != range.second; ++it) {
      LOG(DEBUG) << "Address for " << syscall_name << ": " << std::hex
                 << it->second->start;
      syscall_addresses_.insert(it->second->start);
    }
  }
  return true;
}

bool SyscallAnalyzer::BuildControlFlowGraph() {
  std::set<uint64_t> cuts;
  // Extract the basic blocks. This is done by disassembling instruction by
  // instruction until we reach a block terminator (a branch or return
  // statement). If it doesn't end on a return instruction, the next block is
  // added to the queue.
  struct BlockEntryPoint {
    uint64_t address;
    std::pair<uint64_t, uint64_t> range;
  };
  std::queue<BlockEntryPoint> q;

  for (const auto& symbol_info : symbols_) {
    q.emplace(
        BlockEntryPoint{symbol_info->start,
                        std::make_pair(symbol_info->start, symbol_info->end)});
  }

  while (!q.empty()) {
    BlockEntryPoint bep = q.front();
    q.pop();

    if (block_starts_.find(bep.address) != block_starts_.end())
      continue;

    basic_blocks_.emplace_back(std::make_unique<BasicBlock>(
        bep.address, disassembler_->memory_buffer->getBufferSize()));
    BasicBlock* current_block = basic_blocks_.back().get();
    block_starts_.emplace(current_block->start, current_block);
    for (uint64_t address = bep.address, size = 0; address < bep.range.second;
         address += size) {
      llvm::MCInst instruction;
      disassembler_->disassembler->getInstruction(
          instruction, size,
          llvm::ArrayRef<uint8_t>(
              reinterpret_cast<const uint8_t*>(
                  disassembler_->memory_buffer->getBufferStart() + address),
              reinterpret_cast<const uint8_t*>(
                  disassembler_->memory_buffer->getBufferEnd())),
          address, llvm::nulls(), llvm::nulls());

      if (size == 0)
        size = 1;

      current_block->instructions.emplace_back(address, instruction);

      if (disassembler_->mia->isBranch(instruction) ||
          disassembler_->mia->isCall(instruction)) {
        uint64_t target_address;
        if (disassembler_->mia->evaluateBranch(instruction, address, size,
                                               target_address)) {
          if (bep.range.first <= target_address &&
              target_address < bep.range.second) {
            cuts.emplace(target_address);
            q.emplace(BlockEntryPoint{target_address, bep.range});
          } else {
            auto range = disassembler_->GetExecutableSectionRangeContaining(
                target_address);
            if (range) {
              cuts.emplace(target_address);
              q.emplace(BlockEntryPoint{target_address, *range});
            }
          }
        }
      }
      if (disassembler_->mia->isReturn(instruction) ||
          disassembler_->mia->isUnconditionalBranch(instruction) ||
          address + size >= bep.range.second) {
        cuts.emplace(address + size);
        current_block->end = address + size;
        break;
      }
      if (disassembler_->mia->isTerminator(instruction) ||
          disassembler_->mia->isCall(instruction)) {
        cuts.emplace(address + size);
        current_block->end = address + size;

        auto* previous_block = current_block;
        auto block_it = block_starts_.find(current_block->end);
        if (block_it != block_starts_.end()) {
          current_block = block_it->second;
        } else {
          basic_blocks_.emplace_back(std::make_unique<BasicBlock>(
              current_block->end,
              disassembler_->memory_buffer->getBufferSize()));
          current_block = basic_blocks_.back().get();
          block_starts_.emplace(current_block->start, current_block);
        }
        if (disassembler_->mia->isCall(instruction) ||
            disassembler_->mia->isConditionalBranch(instruction)) {
          previous_block->out_edges.insert(current_block);
          current_block->in_edges.insert(previous_block);
        }
        if (block_it != block_starts_.end())
          break;
      }
    }
  }

  // We have now extracted all the basic blocks, but some in-edges might land
  // smack in the middle of a basic block. This can happen in a loop, since
  // there will be a back-edge. So now go through all basic blocks and try to
  // find any such cut landing in the middle of a block and split it in half.
  {
    std::sort(basic_blocks_.begin(), basic_blocks_.end(),
              [](const auto& a, const auto& b) { return *a < *b; });
    // Since modifying the |basic_blocks_| vector will lead to iterator
    // invalidation, store the newly-split blocks in another vector. We'll
    // merge them later.
    std::vector<std::unique_ptr<BasicBlock>> split_blocks;
    {
      auto it = basic_blocks_.cbegin();
      for (const auto& address : cuts) {
        while (it != basic_blocks_.cend() && (*it)->end <= address)
          ++it;
        if (it == basic_blocks_.cend())
          break;
        if ((*it)->start >= address)
          continue;
        auto previous = (*it)->SplitAt(address);
        block_starts_[previous->start] = previous.get();
        block_starts_[address] = (*it).get();
        split_blocks.emplace_back(std::move(previous));
      }
    }
    for (auto& split_block : split_blocks)
      basic_blocks_.emplace_back(std::move(split_block));
    std::sort(basic_blocks_.begin(), basic_blocks_.end(),
              [](const auto& a, const auto& b) { return *a < *b; });
  }

  // Now that the list of basic blocks has been correctly identified, we can
  // populate the edges that are not fallthrough ones.
  for (const auto& block : basic_blocks_) {
    if (block->instructions.empty())
      continue;
    const uint64_t address = block->instructions.back().first;
    const auto& instruction = block->instructions.back().second;
    const uint64_t size = block->end - address;
    if (!disassembler_->mia->isBranch(instruction) &&
        !disassembler_->mia->isCall(instruction))
      continue;
    uint64_t target_address;
    if (!disassembler_->mia->evaluateBranch(instruction, address, size,
                                            target_address))
      continue;
    if (syscall_addresses_.find(target_address) != syscall_addresses_.end())
      block->ends_with_call_to_syscall = true;
    target_address = LookupTargetAddress(target_address);
    if (syscall_addresses_.find(target_address) != syscall_addresses_.end())
      block->ends_with_call_to_syscall = true;
    auto block_start_address_it = block_starts_.find(target_address);
    if (block_start_address_it == block_starts_.end())
      continue;
    block->out_edges.insert(block_start_address_it->second);
    block_start_address_it->second->in_edges.insert(block.get());
  }

  // Go through all the basic blocks and make the connection between symbols
  // and basic blocks.
  for (const auto& symbol_info : symbols_) {
    symbol_info->entry_point = block_starts_[symbol_info->start];
    symbol_info->entry_point->is_entry_point = true;

    std::queue<BasicBlock*> q({symbol_info->entry_point});
    std::set<BasicBlock*> visited;
    while (!q.empty()) {
      auto* block = q.front();
      q.pop();

      if (!visited.insert(block).second)
        continue;

      if (block->end <= symbol_info->start ||
          symbol_info->end <= block->start) {
        continue;
      }

      block->symbol = symbol_info.get();
      for (BasicBlock* child : block->out_edges)
        q.emplace(child);
    }
  }

  return true;
}

const SyscallAnalyzer::SyscallReport& SyscallAnalyzer::GetSyscallsCalledBy(
    BasicBlock* entry_point) {
  if (syscall_report_map_.find(entry_point) != syscall_report_map_.end())
    return syscall_report_map_.at(entry_point);

  std::set<int> direct_syscalls;
  std::set<BasicBlock*> called_functions;
  LOG(DEBUG) << "Visiting " << *entry_point;
  for (auto* block : entry_point->ReversePostorder()) {
    LOG(DEBUG) << "========= " << *block << " =========";
    if (!block->is_entry_point) {
      for (auto* parent : block->in_edges) {
        for (auto it : parent->registers) {
          auto jt = block->registers.insert(it);
          if (jt.second) {
            // Insertion was successful.
            continue;
          }
          if (jt.first->second == it.second) {
            // Insertion was not successful, but the same value was already
            // there.
            continue;
          }
          // There was a conflict.
          jt.first->second = std::nullopt;
        }
      }
      LOG(DEBUG) << RegisterState{block};
    }

    for (auto& addr_instr : block->instructions) {
      const auto address = addr_instr.first;
      const auto& instruction = addr_instr.second;
      auto& instruction_desc = disassembler_->mii->get(instruction.getOpcode());
      const std::string mnemonic =
          disassembler_->mii->getName(instruction.getOpcode());

      LOG(DEBUG) << std::hex << address << " "
                 << PrintInstruction(instruction, disassembler_->mii.get());
      if (mnemonic == "SYSCALL" ||
          (mnemonic == "INT" && instruction.getOperand(0).isImm() &&
           instruction.getOperand(0).getImm() == 0x80)) {
        auto rax = block->registers.find(disassembler_->syscall_register);
        if (rax == block->registers.end()) {
          LOG(WARN) << "SYSCALL Could not find the value of %rax at "
                    << std::hex << address;
        } else if (rax->second == std::nullopt) {
          LOG(WARN) << "SYSCALL %rax was clobbered at " << std::hex << address;
        } else {
          direct_syscalls.insert(static_cast<int>(rax->second.value()));
        }
        continue;
      }
      if (mnemonic == "SVC" && instruction.getOperand(0).isImm() &&
          instruction.getOperand(0).getImm() == 0x00) {
        auto x8 = block->registers.find(disassembler_->syscall_register);
        if (x8 == block->registers.end()) {
          LOG(WARN) << "SYSCALL Could not find the value of r8/x8 at "
                    << std::hex << address;
        } else if (x8->second == std::nullopt) {
          LOG(WARN) << "SYSCALL r8/x8 was clobbered at " << std::hex << address;
        } else {
          direct_syscalls.insert(static_cast<int>(x8->second.value()));
        }
        continue;
      }
      if (mnemonic.find("NOOP") == 0)
        continue;
      if (instruction_desc.getNumDefs() == 0)
        continue;
      if (!instruction.getOperand(0).isReg())
        continue;
      auto rd_it =
          disassembler_->register_map.find(instruction.getOperand(0).getReg());
      if (rd_it == disassembler_->register_map.end())
        continue;

      std::optional<uint64_t> value = std::nullopt;
      if (instruction_desc.getNumDefs() != 1) {
        value = std::nullopt;
      } else if (mnemonic.find("XOR") == 0 &&
                 instruction_desc.getNumOperands() == 3 &&
                 instruction.getOperand(2).isReg() &&
                 instruction.getOperand(0).getReg() ==
                     instruction.getOperand(2).getReg()) {
        value = std::make_optional(0);
      } else if (instruction_desc.getNumOperands() < 2) {
        value = std::nullopt;
      } else if (mnemonic.find("CMOVE") == 0) {
        // Conditional moves are considered to be clobbering.
        value = std::nullopt;
      } else if (instruction.getOperand(1).isReg()) {
        auto rn_it = disassembler_->register_map.find(
            instruction.getOperand(1).getReg());
        if (rn_it != disassembler_->register_map.end()) {
          auto value_it = block->registers.find(rn_it->second);
          if (value_it != block->registers.end())
            value = value_it->second;
        }
      } else if (instruction.getOperand(1).isImm()) {
        value = std::make_optional(instruction.getOperand(1).getImm());
      }
      // Now that we have the value, clobber any registers that need clobbering.
      for (uint32_t clobber_reg :
           disassembler_
               ->register_clobber_map[instruction.getOperand(0).getReg()]) {
        block->registers[clobber_reg] = std::nullopt;
      }
      block->registers[rd_it->second] = value;
      LOG(DEBUG) << "Updated register state: " << RegisterState{block};
    }

    if (block->ends_with_call_to_syscall) {
      auto nr_register =
          block->registers.find(disassembler_->first_arg_register);
      if (nr_register == block->registers.end()) {
        LOG(WARN) << "SYSCALL Could not find the value of the number at "
                  << std::hex << block->end;
      } else if (nr_register->second == std::nullopt) {
        LOG(WARN) << "SYSCALL number was clobbered at " << std::hex
                  << block->end;
      } else {
        direct_syscalls.insert(static_cast<int>(nr_register->second.value()));
      }
    }

    for (auto* child : block->out_edges) {
      if (child->symbol == block->symbol)
        continue;
      called_functions.insert(child);
    }
  }
  LOG(DEBUG) << "For " << *entry_point
             << " own called syscalls:" << direct_syscalls;
  return syscall_report_map_
      .emplace(entry_point, SyscallReport{direct_syscalls, called_functions})
      .first->second;
}

uint64_t SyscallAnalyzer::LookupTargetAddress(uint64_t target_address) const {
  // First try to see if this is a function that would go through the GOT.
  auto symbol_address_it = symbol_addresses_.find(target_address);
  if (symbol_address_it == symbol_addresses_.end())
    return target_address;
  const std::string& relocated_name = symbol_address_it->second->name;
  if (relocated_name.find("@plt") == std::string::npos)
    return target_address;

  // We may have a version of that function being locally declared.
  const std::string& non_relocated_name =
      relocated_name.substr(0, relocated_name.size() - 4);
  auto symbol_name_it = symbol_names_.find(non_relocated_name);
  if (symbol_name_it == symbol_names_.end())
    return target_address;
  return symbol_name_it->second->start;
}
