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

std::ostream& operator<<(std::ostream& os, const std::set<int>& syscalls) {
  os << "syscalls[" << std::dec;
  for (int syscall_nr : syscalls)
    os << " " << syscall_nr;
  return os << " ]";
}

}  // namespace

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
  if (!symbol->entry_point)
    return {};

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
    if (bep.range.first >= bep.range.second)
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
    if (block_starts_.find(symbol_info->start) == block_starts_.end()) {
      LOG(DEBUG) << "Symbol entry point not found: " << symbol_info->name;
      continue;
    }
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
        for (auto it : parent->processor_state.registers) {
          auto jt = block->processor_state.registers.insert(it);
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
      LOG(DEBUG) << block->processor_state;
    }

    for (auto& addr_instr : block->instructions) {
      const auto address = addr_instr.first;
      const auto& instruction = addr_instr.second;
      const std::string mnemonic =
          disassembler_->mii->getName(instruction.getOpcode());

      LOG(DEBUG) << std::hex << address << " "
                 << PrintInstruction(instruction, disassembler_->mii.get());
      if (mnemonic == "SYSCALL" ||
          (mnemonic == "INT" && instruction.getOperand(0).isImm() &&
           instruction.getOperand(0).getImm() == 0x80) ||
          (mnemonic == "CALL32m" && instruction.getOperand(0).isReg() &&
           instruction.getOperand(0).getReg() == 33 &&
           instruction.getOperand(1).isImm() &&
           instruction.getOperand(1).getImm() == 1 &&
           instruction.getOperand(2).isReg() &&
           instruction.getOperand(2).getReg() == 0 &&
           instruction.getOperand(3).isImm() &&
           instruction.getOperand(3).getImm() == 0 &&
           instruction.getOperand(4).isReg() &&
           instruction.getOperand(4).getReg() == 0)) {
        auto rax = block->processor_state.registers.find(
            disassembler_->syscall_register);
        if (rax == block->processor_state.registers.end()) {
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
        auto x8 = block->processor_state.registers.find(
            disassembler_->syscall_register);
        if (x8 == block->processor_state.registers.end()) {
          LOG(WARN) << "SYSCALL Could not find the value of r8/x8 at "
                    << std::hex << address;
        } else if (x8->second == std::nullopt) {
          LOG(WARN) << "SYSCALL r8/x8 was clobbered at " << std::hex << address;
        } else {
          direct_syscalls.insert(static_cast<int>(x8->second.value()));
        }
        continue;
      }
      if (mnemonic == "tSVC" && instruction.getOperand(0).isImm() &&
          instruction.getOperand(0).getImm() == 0x00) {
        auto r8 = block->processor_state.registers.find(
            disassembler_->syscall_register);
        if (r8 == block->processor_state.registers.end()) {
          LOG(WARN) << "SYSCALL Could not find the value of r8 at " << std::hex
                    << address;
        } else if (r8->second == std::nullopt) {
          LOG(WARN) << "SYSCALL r8 was clobbered at " << std::hex << address;
        } else {
          direct_syscalls.insert(static_cast<int>(r8->second.value()));
        }
        continue;
      }
      disassembler_->UpdateProcessorState(&block->processor_state, instruction);
    }

    if (block->ends_with_call_to_syscall) {
      if (disassembler_->triple.getArch() == llvm::Triple::x86) {
        if (block->processor_state.top_stack == std::nullopt) {
          LOG(WARN) << "SYSCALL number was clobbered at " << std::hex
                    << block->end;
        } else {
          direct_syscalls.insert(
              static_cast<int>(block->processor_state.top_stack.value()));
        }
      } else {
        auto nr_register = block->processor_state.registers.find(
            disassembler_->first_arg_register);
        if (nr_register == block->processor_state.registers.end()) {
          LOG(WARN) << "SYSCALL Could not find the value of the number at "
                    << std::hex << block->end;
        } else if (nr_register->second == std::nullopt) {
          LOG(WARN) << "SYSCALL number was clobbered at " << std::hex
                    << block->end;
        } else {
          direct_syscalls.insert(static_cast<int>(nr_register->second.value()));
        }
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
