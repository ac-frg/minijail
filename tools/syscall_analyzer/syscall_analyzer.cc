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
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/ELF.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
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

// Returns true if |address| is contained in at least one range in |ranges|.
bool ContainedInRange(const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
                      uint64_t address) {
  const auto target =
      std::make_pair(address, std::numeric_limits<uint64_t>::max());
  auto it = std::lower_bound(ranges.begin(), ranges.end(), target);
  if (it == ranges.begin())
    return false;
  --it;
  return it->first <= address && address < it->second;
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

std::unique_ptr<BasicBlock> BasicBlock::SplitAt(uint64_t address) {
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

std::ostream& operator<<(std::ostream& os, const BasicBlock& block) {
  os << "Block{ address: (" << std::hex << block.start << ", " << block.end
     << "), parents: {";
  for (const auto* parent : block.in_edges)
    os << " (" << parent->start << ", " << parent->end << ")";
  os << " }, children: {";
  for (const auto* child : block.out_edges)
    os << " (" << child->start << ", " << child->end << ")";
  os << " }";
  return os;
}

// static
void SyscallAnalyzer::InitLLVM() {
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();
}

// static
std::unique_ptr<SyscallAnalyzer> SyscallAnalyzer::OpenFile(
    std::string_view filename) {
  std::unique_ptr<SyscallAnalyzer> syscall_analyzer(new SyscallAnalyzer());
  if (!syscall_analyzer->LoadFile(filename))
    return nullptr;
  return syscall_analyzer;
}

std::set<std::string> SyscallAnalyzer::GetSymbolNames() const {
  std::set<std::string> symbols;
  for (const auto& symbol_info : symbols_)
    symbols.insert(symbol_info->name);
  return symbols;
}

std::optional<std::set<int>> SyscallAnalyzer::GetSyscallsCalledBy(
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

  std::vector<std::unique_ptr<BasicBlock>> basic_blocks;
  std::map<uint64_t, BasicBlock*> block_starts;
  std::set<uint64_t> cuts;
  std::queue<uint64_t> q({symbol->start});
  while (!q.empty()) {
    uint64_t start_address = q.front();
    q.pop();

    if (block_starts.find(start_address) != block_starts.end())
      continue;

    basic_blocks.emplace_back(std::make_unique<BasicBlock>(
        start_address, memory_buffer_->getBufferSize()));
    BasicBlock* current_block = basic_blocks.back().get();
    if (symbol->start <= current_block->start &&
        current_block->start <= symbol->end) {
      current_block->symbol = symbol;
    }
    block_starts.emplace(current_block->start, current_block);
    for (uint64_t address = start_address, size = 0;
         address < memory_buffer_->getBufferSize(); address += size) {
      llvm::MCInst instruction;
      disassembler_->getInstruction(
          instruction, size,
          llvm::ArrayRef<uint8_t>(
              reinterpret_cast<const uint8_t*>(
                  memory_buffer_->getBufferStart() + address),
              reinterpret_cast<const uint8_t*>(memory_buffer_->getBufferEnd())),
          address, llvm::nulls(), llvm::nulls());

      if (size == 0)
        size = 1;

      current_block->instructions.emplace_back(address, instruction);

      if (mia_->isBranch(instruction) || mia_->isCall(instruction)) {
        uint64_t target_address;
        if (mia_->evaluateBranch(instruction, address, size, target_address)) {
          if (ContainedInRange(executable_section_ranges_, target_address)) {
            cuts.emplace(target_address);
            q.emplace(target_address);
          }
        }
      }
      if ((mia_->isTerminator(instruction) || mia_->isCall(instruction)) &&
          address + size < memory_buffer_->getBufferSize()) {
        cuts.emplace(address + size);
        current_block->end = address + size;
        basic_blocks.emplace_back(std::make_unique<BasicBlock>(
            address + size, memory_buffer_->getBufferSize()));
        auto* previous_block = current_block;
        current_block = basic_blocks.back().get();
        if (symbol->start <= current_block->start &&
            current_block->start <= symbol->end) {
          current_block->symbol = symbol;
        }
        block_starts.emplace(current_block->start, current_block);

        if (mia_->isCall(instruction) ||
            mia_->isConditionalBranch(instruction)) {
          previous_block->out_edges.insert(current_block);
          current_block->in_edges.insert(previous_block);
        }
      }
      if (mia_->isReturn(instruction) ||
          mia_->isUnconditionalBranch(instruction)) {
        cuts.emplace(address + size);
        current_block->end = address + size;
        break;
      }
    }
  }
  symbol->entry_point = block_starts[symbol->start];
  std::sort(basic_blocks.begin(), basic_blocks.end(),
            [](const auto& a, const auto& b) { return *a < *b; });

  {
    std::vector<std::unique_ptr<BasicBlock>> split_blocks;
    {
      auto it = basic_blocks.cbegin();
      for (const auto& address : cuts) {
        while (it != basic_blocks.cend() && (*it)->end <= address)
          ++it;
        if (it == basic_blocks.cend())
          break;
        if ((*it)->start == address)
          continue;
        auto previous = (*it)->SplitAt(address);
        block_starts[previous->start] = previous.get();
        block_starts[address] = (*it).get();
        split_blocks.emplace_back(std::move(previous));
      }
    }
    for (auto& split_block : split_blocks)
      basic_blocks.emplace_back(std::move(split_block));
    std::sort(basic_blocks.begin(), basic_blocks.end(),
              [](const auto& a, const auto& b) { return *a < *b; });
  }

  for (auto& block : basic_blocks) {
    if (block->instructions.empty())
      continue;
    const uint64_t address = block->instructions.back().first;
    const auto& instruction = block->instructions.back().second;
    const uint64_t size = block->end - address;
    if (!mia_->isConditionalBranch(instruction) && !mia_->isCall(instruction))
      continue;
    uint64_t target_address;
    if (!mia_->evaluateBranch(instruction, address, size, target_address))
      continue;
    auto it = block_starts.find(target_address);
    if (it == block_starts.end())
      continue;
    block->out_edges.insert(it->second);
    it->second->in_edges.insert(block.get());
  }

  return std::make_optional(GetSyscallsCalledBy(symbol->entry_point));
}

bool SyscallAnalyzer::LoadFile(std::string_view filename) {
  llvm::Expected<llvm::object::OwningBinary<llvm::object::Binary>>
      binary_or_err = llvm::object::createBinary(filename.data());
  if (!binary_or_err) {
    LOG(ERROR) << "error: could not open " << filename << ": "
               << llvm::toString(binary_or_err.takeError());
    return false;
  }
  llvm::object::OwningBinary<llvm::object::Binary> owning_binary =
      std::move(*binary_or_err);
  std::unique_ptr<llvm::object::Binary> binary;
  std::tie(binary, memory_buffer_) = owning_binary.takeBinary();
  obj_.reset(llvm::dyn_cast<llvm::object::ELFObjectFileBase>(binary.get()));
  if (!obj_) {
    LOG(ERROR) << filename << " is not an ELF object file";
    return false;
  }
  binary.release();

  std::string triple_name = "unknown-unknown-unknown";
  llvm::Triple triple(llvm::Triple::normalize(triple_name));
  triple.setArch(llvm::Triple::ArchType(obj_->getArch()));
  triple_name = triple.getTriple();

  std::string error;
  const llvm::Target* target =
      llvm::TargetRegistry::lookupTarget(triple_name, error);
  if (!target) {
    LOG(ERROR) << error;
    return false;
  }

  mri_.reset(target->createMCRegInfo(triple_name));
  if (!mri_) {
    LOG(ERROR) << "no register info for target " << triple_name;
    return false;
  }

  for (uint32_t i = 0; i < mri_->getNumRegs(); i++) {
    uint32_t superregister = i;
    for (auto it = llvm::MCSuperRegIterator(i, mri_.get(), true); it.isValid();
         ++it) {
      superregister = *it;
    }
    register_map_.emplace(i, superregister);
  }

  mai_.reset(target->createMCAsmInfo(*mri_, triple_name));
  if (!mai_) {
    LOG(ERROR) << "no assembly info for target " << triple_name;
    return false;
  }

  mii_.reset(target->createMCInstrInfo());
  if (!mii_) {
    LOG(ERROR) << "no instruction info for target " << triple_name;
    return false;
  }

  mia_.reset(target->createMCInstrAnalysis(mii_.get()));
  if (!mia_) {
    LOG(ERROR) << "no instruction analysis info for target " << triple_name;
    return false;
  }

  std::string mcpu = "";

  sti_.reset(target->createMCSubtargetInfo(triple_name, mcpu,
                                           obj_->getFeatures().getString()));
  if (!sti_) {
    LOG(ERROR) << "no subtarget info for target " << triple_name;
    return false;
  }

  mofi_ = std::make_unique<llvm::MCObjectFileInfo>();
  ctx_ = std::make_unique<llvm::MCContext>(mai_.get(), mri_.get(), mofi_.get());
  mofi_->InitMCObjectFileInfo(triple, false, llvm::CodeModel::Default, *ctx_);

  disassembler_.reset(target->createMCDisassembler(*sti_, *ctx_));
  if (!disassembler_) {
    LOG(ERROR) << "no disassembler for target " << triple_name;
    return false;
  }

  for (const llvm::object::SectionRef& section : obj_->sections()) {
    if (!section.isText() || section.isVirtual())
      continue;

    executable_section_ranges_.emplace_back(
        section.getAddress(), section.getAddress() + section.getSize());
  }
  std::sort(executable_section_ranges_.begin(),
            executable_section_ranges_.end());

  // Collect normal and dynamic symbols.
  for (const llvm::object::SymbolRef& symbol : obj_->symbols()) {
    llvm::Expected<uint64_t> address = symbol.getAddress();
    if (!address) {
      LOG(ERROR) << "no symbol address";
      return false;
    }

    if (!ContainedInRange(executable_section_ranges_, *address))
      continue;

    llvm::Expected<llvm::StringRef> name = symbol.getName();
    if (!name) {
      LOG(ERROR) << "no symbol name for symbol at " << std::hex << *address;
      return false;
    }
    if (name->empty())
      continue;

    symbols_.emplace_back(std::make_unique<SymbolInfo>(
        *address, *address + symbol.getCommonSize(), name->str()));
  }
  for (const llvm::object::ELFSymbolRef& symbol :
       obj_->getDynamicSymbolIterators()) {
    llvm::Expected<uint64_t> address = symbol.getAddress();
    if (!address) {
      LOG(ERROR) << "no symbol address";
      return false;
    }

    if (!ContainedInRange(executable_section_ranges_, *address))
      continue;

    llvm::Expected<llvm::StringRef> name = symbol.getName();
    if (!name) {
      LOG(ERROR) << "no symbol name for symbol at " << std::hex << *address;
      return false;
    }
    if (name->empty())
      continue;

    symbols_.emplace_back(std::make_unique<SymbolInfo>(
        *address, *address + symbol.getSize(), name->str()));
  }
  std::sort(symbols_.begin(), symbols_.end(),
            [](const auto& a, const auto& b) { return *a < *b; });

  return true;
}

const std::set<int>& SyscallAnalyzer::GetSyscallsCalledBy(
    BasicBlock* entry_point) {
  if (syscall_map_.find(entry_point) != syscall_map_.end())
    return syscall_map_.at(entry_point);

  std::set<int> called_syscalls;
  std::set<BasicBlock*> called_functions;
  LOG(DEBUG) << "Visiting " << *entry_point;
  for (auto* block : entry_point->ReversePostorder()) {
    LOG(DEBUG) << "========= " << *block << " =========";
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

    for (auto& addr_instr : block->instructions) {
      const auto address = addr_instr.first;
      const auto& instruction = addr_instr.second;
      auto& instruction_desc = mii_->get(instruction.getOpcode());
      const std::string mnemonic = mii_->getName(instruction.getOpcode());

      {
        std::string buf;
        {
          llvm::raw_string_ostream os(buf);
          instruction.dump_pretty(os);
        }
        LOG(DEBUG) << std::hex << address << " " << mnemonic << " " << buf;
      }
      if (mnemonic == "SYSCALL" ||
          (mnemonic == "INT" && instruction.getOperand(0).isImm() &&
           instruction.getOperand(0).getImm() == 0x80)) {
        auto rax = block->registers.find(35);
        if (rax == block->registers.end()) {
          LOG(WARN) << "SYSCALL Could not find the value of %rax! at "
                    << std::hex << address;
        }
        if (rax->second == std::nullopt)
          LOG(WARN) << "SYSCALL %rax was clobbered at " << std::hex << address;
        else
          called_syscalls.insert(static_cast<int>(rax->second.value()));
        continue;
      }
      if (mnemonic == "SVC" && instruction.getOperand(0).isImm() &&
          instruction.getOperand(0).getImm() == 0x00) {
        auto x8 = block->registers.find(464);
        if (x8 == block->registers.end()) {
          LOG(WARN) << "SYSCALL Could not find the value of %x8! at "
                    << std::hex << address;
        }
        if (x8->second == std::nullopt)
          LOG(WARN) << "SYSCALL %x8 was clobbered at " << std::hex << address;
        else
          called_syscalls.insert(static_cast<int>(x8->second.value()));
        continue;
      }
      if (mnemonic.find("NOOP") == 0)
        continue;
      if (instruction_desc.getNumDefs() == 0)
        continue;
      if (instruction_desc.getNumDefs() != 1) {
        LOG(WARN) << std::hex << address << "  " << mnemonic
                  << ": unexpected number of defs: "
                  << instruction_desc.getNumDefs();
        continue;
      }
      if (!instruction.getOperand(0).isReg())
        continue;

      if (mnemonic.find("XOR") == 0 && instruction_desc.getNumOperands() == 3 &&
          instruction.getOperand(2).isReg() &&
          instruction.getOperand(0).getReg() ==
              instruction.getOperand(2).getReg()) {
        block->registers[register_map_.at(instruction.getOperand(0).getReg())] =
            std::make_optional(0);
      } else if (instruction_desc.getNumOperands() < 2) {
        block->registers[register_map_.at(instruction.getOperand(0).getReg())] =
            std::nullopt;
      } else if (instruction.getOperand(1).isReg()) {
        auto it = block->registers.find(
            register_map_.at(instruction.getOperand(1).getReg()));
        if (it == block->registers.end()) {
          block->registers[register_map_.at(
              instruction.getOperand(0).getReg())] = std::nullopt;
        } else {
          block->registers[register_map_.at(
              instruction.getOperand(0).getReg())] = it->second;
        }
      } else if (instruction.getOperand(1).isImm()) {
        block->registers[register_map_.at(instruction.getOperand(0).getReg())] =
            std::make_optional(instruction.getOperand(1).getImm());
      }
      LOG(DEBUG) << "Updated register state: " << RegisterState{block};
    }

    for (auto* child : block->out_edges) {
      if (child->symbol == block->symbol)
        continue;
      called_functions.insert(child);
    }
  }
  {
    std::ostringstream buf;
    for (int syscall_nr : called_syscalls) {
      buf << " " << syscall_nr;
    }
    LOG(DEBUG) << "For " << *entry_point
               << " own called syscalls:" << buf.str();
  }
  syscall_map_.emplace(entry_point, called_syscalls);

  for (auto* child : called_functions) {
    const auto& child_syscalls = GetSyscallsCalledBy(child);
    syscall_map_.at(entry_point)
        .insert(child_syscalls.begin(), child_syscalls.end());
  }
  return syscall_map_.at(entry_point);
}
