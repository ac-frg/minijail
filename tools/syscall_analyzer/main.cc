/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <set>
#include <string>

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrAnalysis.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/Object/Archive.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/ELFObjectFile.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/ELF.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_os_ostream.h>

namespace {

struct BasicBlock;

struct SymbolInfo {
  uint64_t start;
  uint64_t end;
  std::string name;
  llvm::object::SymbolRef symbol;
  BasicBlock* entry_point = nullptr;

  SymbolInfo(uint64_t start,
             uint64_t end,
             std::string name,
             llvm::object::SymbolRef symbol)
      : start(start),
        end(end),
        name(std::move(name)),
        symbol(std::move(symbol)) {}

  bool operator<(const SymbolInfo& o) const {
    if (start == o.start)
      return end < o.end;
    return start < o.start;
  };
};

struct BasicBlock {
  uint64_t start;
  uint64_t end;
  std::vector<std::pair<uint64_t, llvm::MCInst>> instructions{};
  SymbolInfo* symbol = nullptr;

  BasicBlock(uint64_t start, uint64_t end) : start(start), end(end) {}

  std::set<BasicBlock*> out_edges;
  std::set<BasicBlock*> in_edges;
  std::map<uint32_t, std::optional<int64_t>> registers;

  bool operator<(const BasicBlock& o) const {
    if (start == o.start)
      return end < o.end;
    return start < o.start;
  };

  std::unique_ptr<BasicBlock> SplitAt(uint64_t address) {
    auto previous = std::make_unique<BasicBlock>(start, address);
    start = address;
    auto it = instructions.begin();
    for (; it != instructions.end() && it->first < address; ++it)
      previous->instructions.emplace_back(it->first, std::move(it->second));
    instructions.erase(instructions.begin(), it);
    previous->out_edges.insert(this);
    in_edges.insert(previous.get());
    return previous;
  }

  void PrintRegisterState() {
    for (const auto it : registers) {
      std::cout << "reg[" << std::dec << it.first << "] = ";
      if (it.second == std::nullopt)
        std::cout << "<clobbered>";
      else
        std::cout << std::hex << it.second.value();
      std::cout << " ";
    }
    std::cout << "\n";
  }
};

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

void ReversePostorderImpl(BasicBlock* current,
                          std::vector<BasicBlock*>* out_blocks,
                          std::set<BasicBlock*>* visited) {
  if (visited->find(current) != visited->end())
    return;
  visited->insert(current);
  for (auto* next : current->out_edges) {
    if (next->symbol != current->symbol)
      continue;
    ReversePostorderImpl(next, out_blocks, visited);
  }
  out_blocks->emplace_back(current);
}

std::vector<BasicBlock*> ReversePostorder(BasicBlock* entry) {
  std::vector<BasicBlock*> result;
  std::set<BasicBlock*> visited;
  ReversePostorderImpl(entry, &result, &visited);
  std::reverse(result.begin(), result.end());
  return result;
}

bool DisassembleObject(const llvm::object::ELFObjectFileBase* obj) {
  std::string triple_name = "unknown-unknown-unknown";
  llvm::Triple triple(llvm::Triple::normalize(triple_name));
  triple.setArch(llvm::Triple::ArchType(obj->getArch()));
  triple_name = triple.getTriple();

  std::string error;
  const llvm::Target* target =
      llvm::TargetRegistry::lookupTarget(triple_name, error);
  if (!target) {
    std::cerr << "error: " << error;
    return false;
  }

  std::unique_ptr<const llvm::MCRegisterInfo> mri(
      target->createMCRegInfo(triple_name));
  if (!mri) {
    std::cerr << "error: no register info for target " << triple_name << "\n";
    return false;
  }

  std::map<uint32_t, uint32_t> register_map;
  for (uint32_t i = 0; i < mri->getNumRegs(); i++) {
    uint32_t superregister = i;
    for (auto it = llvm::MCSuperRegIterator(i, mri.get(), true); it.isValid();
         ++it) {
      superregister = *it;
    }
    register_map.emplace(i, superregister);
  }

  std::unique_ptr<const llvm::MCAsmInfo> mai(
      target->createMCAsmInfo(*mri, triple_name));
  if (!mai) {
    std::cerr << "error: no assembly info for target " << triple_name << "\n";
    return false;
  }

  std::unique_ptr<const llvm::MCInstrInfo> mii(target->createMCInstrInfo());
  if (!mii) {
    std::cerr << "error: no instruction info for target " << triple_name
              << "\n";
    return false;
  }

  std::unique_ptr<const llvm::MCInstrAnalysis> mia(
      target->createMCInstrAnalysis(mii.get()));
  if (!mia) {
    std::cerr << "error: no instruction analysis info for target "
              << triple_name << "\n";
    return false;
  }

  std::string mcpu = "";

  std::unique_ptr<llvm::MCSubtargetInfo> sti(target->createMCSubtargetInfo(
      triple_name, mcpu, obj->getFeatures().getString()));
  if (!sti) {
    std::cerr << "error: no subtarget info for target " << triple_name << "\n";
    return false;
  }

  llvm::MCObjectFileInfo mofi;
  llvm::MCContext ctx(mai.get(), mri.get(), &mofi);
  mofi.InitMCObjectFileInfo(triple, false, llvm::CodeModel::Default, ctx);

  std::unique_ptr<const llvm::MCDisassembler> disassembler(
      target->createMCDisassembler(*sti, ctx));
  if (!disassembler) {
    std::cerr << "error: no disassembler for target " << triple_name << "\n";
    return false;
  }

  std::vector<std::pair<uint64_t, uint64_t>> section_ranges;
  for (const llvm::object::SectionRef& section : obj->sections()) {
    if (!section.isText() || section.isVirtual())
      continue;

    section_ranges.emplace_back(section.getAddress(),
                                section.getAddress() + section.getSize());
  }
  std::sort(section_ranges.begin(), section_ranges.end());

  // Collect normal and dynamic symbols.
  std::vector<std::unique_ptr<SymbolInfo>> all_symbols;
  for (const llvm::object::SymbolRef& symbol : obj->symbols()) {
    llvm::Expected<uint64_t> address = symbol.getAddress();
    if (!address) {
      std::cerr << "error: no symbol address\n";
      return false;
    }

    if (!ContainedInRange(section_ranges, *address))
      continue;

    llvm::Expected<llvm::StringRef> name = symbol.getName();
    if (!name) {
      std::cerr << "error: no symbol name for symbol at " << std::hex
                << *address << "\n";
      return false;
    }
    if (name->empty())
      continue;

    all_symbols.emplace_back(std::make_unique<SymbolInfo>(
        *address, *address + symbol.getCommonSize(), name->str(), symbol));
  }
  for (const llvm::object::ELFSymbolRef& symbol :
       obj->getDynamicSymbolIterators()) {
    llvm::Expected<uint64_t> address = symbol.getAddress();
    if (!address) {
      std::cerr << "error: no symbol address\n";
      return false;
    }

    if (!ContainedInRange(section_ranges, *address))
      continue;

    llvm::Expected<llvm::StringRef> name = symbol.getName();
    if (!name) {
      std::cerr << "error: no symbol name for symbol at " << std::hex
                << *address << "\n";
      return false;
    }
    if (name->empty())
      continue;

    all_symbols.emplace_back(std::make_unique<SymbolInfo>(
        *address, *address + symbol.getSize(), name->str(), symbol));
  }
  std::sort(all_symbols.begin(), all_symbols.end(),
            [](const std::unique_ptr<SymbolInfo>& a,
               const std::unique_ptr<SymbolInfo>& b) { return *a < *b; });

  std::set<uint64_t> cuts;
  for (const auto& symbol_info : all_symbols) {
    cuts.emplace(symbol_info->start);
    cuts.emplace(symbol_info->end);
  }

  std::vector<std::unique_ptr<BasicBlock>> basic_blocks;
  std::map<uint64_t, BasicBlock*> block_starts;
  for (const llvm::object::SectionRef& section : obj->sections()) {
    if (!section.isText() || section.isVirtual())
      continue;

    const uint64_t section_start = section.getAddress();
    const uint64_t section_size = section.getSize();
    if (!section_size)
      continue;

    llvm::StringRef name;
    section.getName(name);

    llvm::StringRef bytes_str;
    section.getContents(bytes_str);
    llvm::ArrayRef<uint8_t> bytes(
        reinterpret_cast<const uint8_t*>(bytes_str.data()), bytes_str.size());

    basic_blocks.emplace_back(std::make_unique<BasicBlock>(
        section_start, section_start + section_size));
    BasicBlock* current_block = basic_blocks.back().get();
    block_starts.emplace(current_block->start, current_block);
    for (uint64_t index = 0, size = 0; index < section_size; index += size) {
      llvm::MCInst instruction;
      const uint64_t address = section_start + index;

      disassembler->getInstruction(instruction, size, bytes.slice(index),
                                   address, llvm::nulls(), llvm::nulls());

      if (size == 0)
        size = 1;

      current_block->instructions.emplace_back(address, instruction);

      if (mia->isBranch(instruction)) {
        uint64_t target_address;
        if (mia->evaluateBranch(instruction, address, size, target_address)) {
          if (ContainedInRange(section_ranges, target_address)) {
            cuts.emplace(target_address);
          }
        }
      }
      if (mia->isTerminator(instruction) &&
          address + size < section_start + section_size) {
        cuts.emplace(address + size);
        current_block->end = address + size;
        basic_blocks.emplace_back(std::make_unique<BasicBlock>(
            address + size, section_start + section_size));
        auto* previous_block = current_block;
        current_block = basic_blocks.back().get();
        block_starts.emplace(current_block->start, current_block);

        if (mia->isCall(instruction) || mia->isConditionalBranch(instruction)) {
          previous_block->out_edges.insert(current_block);
          current_block->in_edges.insert(previous_block);
        }
      }
    }
  }
  std::sort(basic_blocks.begin(), basic_blocks.end(),
            [](const std::unique_ptr<BasicBlock>& a,
               const std::unique_ptr<BasicBlock>& b) { return *a < *b; });

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
              [](const std::unique_ptr<BasicBlock>& a,
                 const std::unique_ptr<BasicBlock>& b) { return *a < *b; });
  }

  for (auto& block : basic_blocks) {
    if (block->instructions.empty())
      continue;
    const uint64_t address = block->instructions.back().first;
    const auto& instruction = block->instructions.back().second;
    const uint64_t size = block->end - address;
    if (!mia->isConditionalBranch(instruction) && !mia->isCall(instruction))
      continue;
    uint64_t target_address;
    if (!mia->evaluateBranch(instruction, address, size, target_address))
      continue;
    auto it = block_starts.find(target_address);
    if (it == block_starts.end())
      continue;
    block->out_edges.insert(it->second);
    it->second->in_edges.insert(block.get());
  }

  for (auto& symbol_info : all_symbols) {
    auto it = block_starts.find(symbol_info->start);
    if (it == block_starts.end()) {
      std::cerr << "Could not find entry point for " << symbol_info->name
                << "\n";
      continue;
    }
    it->second->symbol = symbol_info.get();
    symbol_info->entry_point = it->second;

    std::queue<BasicBlock*> q({symbol_info->entry_point});
    std::set<BasicBlock*> visited;

    while (!q.empty()) {
      auto* current = q.front();
      q.pop();

      if (current->end <= symbol_info->start ||
          symbol_info->end <= current->start) {
        continue;
      }

      if (visited.find(current) != visited.end())
        continue;
      visited.insert(current);

      current->symbol = symbol_info.get();

      for (auto* next : current->out_edges)
        q.push(next);
    }

    std::cout << "Visiting all blocks in " << symbol_info->name << "\n";
    for (auto* block : ReversePostorder(symbol_info->entry_point)) {
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
      for (auto& addr_instr : block->instructions) {
        const auto address = addr_instr.first;
        const auto& instruction = addr_instr.second;
        auto& instruction_desc = mii->get(instruction.getOpcode());
        const std::string mnemonic = mii->getName(instruction.getOpcode());
        if (mnemonic == "SYSCALL") {
          auto rax = block->registers.find(35);
          if (rax == block->registers.end()) {
            std::cerr
                << "\n\n\nSYSCALL Could not find the value of %rax!\n\n\n";
            abort();
          }
          if (rax->second == std::nullopt) {
            std::cerr << "SYSCALL %rax was clobbered at " << std::hex << address
                      << "\n";
          } else {
            std::cout << "SYSCALL " << std::dec << rax->second.value() << "\n";
          }
        }
        if (mnemonic.find("NOOP") == 0)
          continue;
        if (instruction_desc.getNumDefs() == 0)
          continue;
        if (instruction_desc.getNumDefs() != 1) {
          std::cerr << "\n\n\n" << instruction_desc.getNumDefs() << "\n\n\n";
          abort();
        }
        if (!instruction.getOperand(0).isReg())
          continue;

        if (mnemonic.find("XOR") == 0 &&
            instruction_desc.getNumOperands() == 3 &&
            instruction.getOperand(2).isReg() &&
            instruction.getOperand(0).getReg() ==
                instruction.getOperand(2).getReg()) {
          block->registers[register_map[instruction.getOperand(0).getReg()]] =
              std::make_optional(0);
        } else if (instruction_desc.getNumOperands() != 2) {
          block->registers[register_map[instruction.getOperand(0).getReg()]] =
              std::nullopt;
        } else if (instruction.getOperand(1).isReg()) {
          auto it = block->registers.find(
              register_map[instruction.getOperand(1).getReg()]);
          if (it == block->registers.end()) {
            block->registers[register_map[instruction.getOperand(0).getReg()]] =
                std::nullopt;
          } else {
            block->registers[register_map[instruction.getOperand(0).getReg()]] =
                it->second;
          }
        } else if (instruction.getOperand(1).isImm()) {
          block->registers[register_map[instruction.getOperand(0).getReg()]] =
              std::make_optional(instruction.getOperand(1).getImm());
        }
      }
    }
  }

  return true;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <library>";
    return 1;
  }

  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();

  llvm::Expected<llvm::object::OwningBinary<llvm::object::Binary>>
      binary_or_err = llvm::object::createBinary(argv[1]);
  if (!binary_or_err) {
    std::cerr << "error: could not open " << argv[1] << ": "
              << llvm::toString(binary_or_err.takeError()) << "\n";
    return 1;
  }
  llvm::object::Binary& binary = *binary_or_err.get().getBinary();
  llvm::object::ELFObjectFileBase* obj =
      llvm::dyn_cast<llvm::object::ELFObjectFileBase>(&binary);
  if (!obj) {
    std::cerr << "error: " << argv[1] << " is not an ELF object file\n";
    return 1;
  }

  if (!DisassembleObject(obj)) {
    return 1;
  }
  return 0;
}
