/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "disassembler.h"

#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

#include "logging.h"

namespace {

// This is not guaranteed to be the correct size, but it just so happens to be
// this way in all versions of Bionic and GLibc that we're interested in.
constexpr size_t kPltEntrySize = 0x10;

// Returns true if |address| is contained in at least one range in |ranges|.
std::optional<std::pair<uint64_t, uint64_t>> GetContainingRange(
    const std::vector<std::pair<uint64_t, uint64_t>>& ranges,
    uint64_t address) {
  const auto target =
      std::make_pair(address, std::numeric_limits<uint64_t>::max());
  auto it = std::lower_bound(ranges.begin(), ranges.end(), target);
  if (it == ranges.begin())
    return std::nullopt;
  --it;
  if (address < it->first || it->second <= address)
    return std::nullopt;
  return std::make_optional(*it);
}

uint32_t RotateRight(uint32_t x, uint32_t n) {
  return ((x >> n) | (x << (32 - n)));
}

uint32_t DecodeARMImmediate(uint64_t imm) {
  return RotateRight(static_cast<uint32_t>(imm & 0xff),
                     static_cast<uint32_t>((imm >> 7) & 0x1e));
}

// Gets the address into the .got.plt for a PLT entry.
std::optional<uint64_t> GetGotPltAddress(
    uint32_t arch,
    const llvm::MCDisassembler* disassembler,
    const llvm::MCInstrInfo* mii,
    const llvm::MemoryBuffer* memory_buffer,
    uint64_t address,
    uint64_t got_plt_address) {
  // Decoding 3 instructions is enough in all architectures we are interested
  // in.
  std::pair<llvm::MCInst, std::string> instructions[3];
  uint64_t instruction_address = address;
  for (auto& instruction : instructions) {
    uint64_t size;
    if (disassembler->getInstruction(
            instruction.first, size,
            llvm::ArrayRef<uint8_t>(
                reinterpret_cast<const uint8_t*>(
                    memory_buffer->getBufferStart() + instruction_address),
                reinterpret_cast<const uint8_t*>(
                    memory_buffer->getBufferEnd())),
            instruction_address, llvm::nulls(),
            llvm::nulls()) == llvm::MCDisassembler::DecodeStatus::Fail) {
      LOG(DEBUG) << "Failed to decode instruction at " << std::hex
                 << instruction_address;
      return std::nullopt;
    }
    instruction.second = mii->getName(instruction.first.getOpcode());
    instruction_address += size;
  }

  // This uses roughly the same approach as GNU's objdump, which is to sniff
  // the instructions in each PLT entry.
  if (arch == llvm::Triple::aarch64) {
    if (instructions[0].second != "ADRP" ||
        instructions[1].second != "LDRXui" ||
        instructions[2].second != "ADDXri") {
      return std::nullopt;
    }
    return ((address + (instructions[0].first.getOperand(1).getImm() << 12)) &
            0xFFFFFFFFFFFFF000ULL) |
           (instructions[1].first.getOperand(2).getImm() << 3);
  } else if (arch == llvm::Triple::arm) {
    if (instructions[0].second != "ADDri" ||
        instructions[1].second != "ADDri" ||
        instructions[2].second != "LDR_PRE_IMM") {
      return std::nullopt;
    }
    // ARM's PC is always pointing to the instruction after the current one,
    // hence the +8.
    return (address + 8 +
            DecodeARMImmediate(instructions[0].first.getOperand(2).getImm()) +
            DecodeARMImmediate(instructions[1].first.getOperand(2).getImm()) +
            instructions[2].first.getOperand(3).getImm());
  } else if (arch == llvm::Triple::x86) {
    if (instructions[0].second != "JMP32m" ||
        instructions[1].second != "PUSHi32" ||
        instructions[2].second != "JMP_4") {
      return std::nullopt;
    }
    // Bionic x86 assumes that the GOT's address is already on the register.
    return got_plt_address + instructions[0].first.getOperand(3).getImm();
  } else if (arch == llvm::Triple::x86_64) {
    if (instructions[0].second != "JMP64m" ||
        instructions[1].second != "PUSH64i32" ||
        instructions[2].second != "JMP_4") {
      return std::nullopt;
    }
    // x86_64 PC-relative JMP is taken from the end of the instruction.
    return address + 6 + instructions[0].first.getOperand(3).getImm();
  }
  return std::nullopt;
}

// Gets a list of symbols that don't have an explicit entry in the ELF file.
// These currently are the entries in the .plt section.
std::vector<std::unique_ptr<SymbolInfo>> GetSyntheticSymbols(
    const llvm::object::ELFObjectFileBase* obj,
    const llvm::MCDisassembler* disassembler,
    const llvm::MCInstrInfo* mii,
    const llvm::MemoryBuffer* memory_buffer) {
  std::optional<llvm::object::SectionRef> plt_section = std::nullopt,
                                          got_plt_section = std::nullopt,
                                          rel_plt_section = std::nullopt;
  for (const llvm::object::SectionRef& section : obj->sections()) {
    llvm::StringRef name;
    if (section.getName(name))
      continue;
    if (name == ".plt")
      plt_section = section;
    if (name == ".got.plt")
      got_plt_section = section;
    if (name == ".rel.plt" || name == ".rela.plt")
      rel_plt_section = section;
  }
  if (!plt_section || !got_plt_section || !rel_plt_section)
    return {};

  std::map<uint64_t, std::string> symbol_names;
  for (const auto& relocation : rel_plt_section->relocations()) {
    auto symbol = relocation.getSymbol();
    if (symbol == obj->symbol_end())
      continue;
    llvm::Expected<llvm::StringRef> expected_relocated_symbol_name =
        symbol->getName();
    if (!expected_relocated_symbol_name)
      continue;
    symbol_names.emplace(relocation.getOffset(),
                         *expected_relocated_symbol_name);
  }

  std::vector<std::unique_ptr<SymbolInfo>> result;
  for (uint64_t plt_address = plt_section->getAddress();
       plt_address < plt_section->getAddress() + plt_section->getSize();
       plt_address += kPltEntrySize) {
    std::optional<uint64_t> got_plt_address =
        GetGotPltAddress(obj->getArch(), disassembler, mii, memory_buffer,
                         plt_address, got_plt_section->getAddress());
    if (!got_plt_address)
      continue;
    const auto it = symbol_names.find(*got_plt_address);
    if (it == symbol_names.end())
      continue;
    result.emplace_back(std::make_unique<SymbolInfo>(
        plt_address, plt_address + kPltEntrySize, it->second + "@plt"));
  }
  std::sort(result.begin(), result.end());
  return result;
}

}  // namespace

// static
void Disassembler::InitLLVM() {
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllDisassemblers();
}

bool Disassembler::CreateLLVMObjectsForTriple(
    llvm::Triple triple,
    std::string_view subtarget_features) {
  this->triple = triple;

  std::string triple_name = triple.getTriple();

  std::string error;
  const llvm::Target* target =
      llvm::TargetRegistry::lookupTarget(triple_name, error);
  if (!target) {
    LOG(ERROR) << error;
    return false;
  }

  mri.reset(target->createMCRegInfo(triple_name));
  if (!mri) {
    LOG(ERROR) << "no register info for target " << triple_name;
    return false;
  }

  mai.reset(target->createMCAsmInfo(*mri, triple_name));
  if (!mai) {
    LOG(ERROR) << "no assembly info for target " << triple_name;
    return false;
  }

  mii.reset(target->createMCInstrInfo());
  if (!mii) {
    LOG(ERROR) << "no instruction info for target " << triple_name;
    return false;
  }

  mia.reset(target->createMCInstrAnalysis(mii.get()));
  if (!mia) {
    LOG(ERROR) << "no instruction analysis info for target " << triple_name;
    return false;
  }

  std::string mcpu = "";

  sti.reset(target->createMCSubtargetInfo(triple_name, mcpu,
                                          std::string(subtarget_features)));
  if (!sti) {
    LOG(ERROR) << "no subtarget info for target " << triple_name;
    return false;
  }

  mofi = std::make_unique<llvm::MCObjectFileInfo>();
  ctx = std::make_unique<llvm::MCContext>(mai.get(), mri.get(), mofi.get());

  disassembler.reset(target->createMCDisassembler(*sti, *ctx));
  if (!disassembler) {
    LOG(ERROR) << "no disassembler for target " << triple_name;
    return false;
  }

  // Gather information about the arch's registers.
  for (uint32_t i = 0; i < mri->getNumRegClasses(); ++i) {
    const auto& reg_class = mri->getRegClass(i);
    std::string reg_class_name = mri->getRegClassName(&reg_class);
    bool is_gp_register_class = false;
    switch (triple.getArch()) {
      case llvm::Triple::aarch64:
        is_gp_register_class = reg_class_name == "GPR64";
        break;
      case llvm::Triple::arm:
        is_gp_register_class = reg_class_name == "GPR";
        break;
      case llvm::Triple::x86:
      case llvm::Triple::x86_64:
        is_gp_register_class = reg_class_name == "GR64";
        break;
      default:
        LOG(FATAL) << "Unsupported architecture " << triple_name;
    }
    if (!is_gp_register_class)
      continue;
    for (uint32_t j = 0; j < reg_class.getNumRegs(); ++j) {
      uint32_t reg_num = reg_class.getRegister(j);
      std::string register_name = mri->getName(reg_num);
      switch (triple.getArch()) {
        case llvm::Triple::aarch64:
          if (register_name == "X8")
            syscall_register = reg_num;
          else if (register_name == "X0")
            first_arg_register = reg_num;
          break;
        case llvm::Triple::arm:
          if (register_name == "R7")
            syscall_register = reg_num;
          else if (register_name == "R0")
            first_arg_register = reg_num;
          break;
        case llvm::Triple::x86:
        case llvm::Triple::x86_64:
          if (register_name == "RAX")
            syscall_register = reg_num;
          else if (register_name == "RDI")
            first_arg_register = reg_num;
          break;
        default:
          LOG(FATAL) << "Unsupported architecture " << triple_name;
      }
      for (auto it = llvm::MCSubRegIterator(reg_num, mri.get(), true);
           it.isValid(); ++it) {
        register_map.emplace(*it, reg_num);
        LOG(DEBUG) << "Register " << *it << " maps to " << reg_num;
      }
      for (auto it = llvm::MCSuperRegIterator(reg_num, mri.get(), false);
           it.isValid(); ++it) {
        register_clobber_map[*it].insert(reg_num);
        LOG(DEBUG) << "Register " << *it << " clobbers " << reg_num;
      }
    }
  }
  if (syscall_register == 0) {
    LOG(ERROR) << "Could not find the syscall register for this architecture";
    return false;
  }
  if (first_arg_register == 0) {
    LOG(ERROR)
        << "Could not find the first argument register for this architecture";
    return false;
  }

  return true;
}

Disassembler::Disassembler() = default;
Disassembler::~Disassembler() = default;

std::optional<std::pair<uint64_t, uint64_t>>
Disassembler::GetExecutableSectionRangeContaining(uint64_t address) {
  return std::nullopt;
}

// static
std::unique_ptr<ELFFileDisassembler> ELFFileDisassembler::OpenFile(
    std::string_view filename) {
  llvm::Expected<llvm::object::OwningBinary<llvm::object::Binary>>
      binary_or_err = llvm::object::createBinary(filename.data());
  if (!binary_or_err) {
    LOG(ERROR) << "error: could not open " << filename << ": "
               << llvm::toString(binary_or_err.takeError());
    return nullptr;
  }
  llvm::object::OwningBinary<llvm::object::Binary> owning_binary =
      std::move(*binary_or_err);
  std::unique_ptr<llvm::object::Binary> binary;
  std::unique_ptr<ELFFileDisassembler> disassembler(new ELFFileDisassembler());
  std::tie(binary, disassembler->memory_buffer) = owning_binary.takeBinary();
  disassembler->obj_.reset(
      llvm::dyn_cast<llvm::object::ELFObjectFileBase>(binary.get()));
  if (!disassembler->obj_) {
    LOG(ERROR) << filename << " is not an ELF object file";
    return nullptr;
  }
  // We already have a reference to this object in |_obj_|.
  binary.release();

  llvm::Triple triple(llvm::Triple::normalize("unknown-unknown-unknown"));
  triple.setArch(llvm::Triple::ArchType(disassembler->obj_->getArch()));

  if (!disassembler->CreateLLVMObjectsForTriple(
          triple, disassembler->obj_->getFeatures().getString()))
    return nullptr;

  return disassembler;
}

ELFFileDisassembler::ELFFileDisassembler() = default;
ELFFileDisassembler::~ELFFileDisassembler() = default;

bool ELFFileDisassembler::GetSymbols(
    std::vector<std::unique_ptr<SymbolInfo>>* out_symbols) {
  if (!out_symbols)
    return false;

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
    if (!GetExecutableSectionRangeContaining(*address))
      continue;

    llvm::Expected<llvm::StringRef> name = symbol.getName();
    if (!name) {
      LOG(ERROR) << "no symbol name for symbol at " << std::hex << *address;
      return false;
    }
    if (name->empty())
      continue;

    LOG(DEBUG) << "Normal symbol " << name->str() << " " << std::hex << *address
               << " size " << symbol.getCommonSize();

    out_symbols->emplace_back(std::make_unique<SymbolInfo>(
        *address, *address + symbol.getCommonSize(), name->str()));
  }
  for (const llvm::object::ELFSymbolRef& symbol :
       obj_->getDynamicSymbolIterators()) {
    llvm::Expected<uint64_t> address = symbol.getAddress();
    if (!address) {
      LOG(ERROR) << "no symbol address";
      return false;
    }

    if (!GetExecutableSectionRangeContaining(*address))
      continue;

    llvm::Expected<llvm::StringRef> name = symbol.getName();
    if (!name) {
      LOG(ERROR) << "no symbol name for symbol at " << std::hex << *address;
      return false;
    }
    if (name->empty())
      continue;

    LOG(DEBUG) << "Dynamic symbol " << name->str() << " " << std::hex
               << *address << " type "
               << static_cast<uint32_t>(symbol.getELFType()) << " size "
               << symbol.getSize();

    out_symbols->emplace_back(std::make_unique<SymbolInfo>(
        *address, *address + symbol.getSize(), name->str()));
  }
  for (auto& synthetic_symbol : GetSyntheticSymbols(
           obj_.get(), disassembler.get(), mii.get(), memory_buffer.get())) {
    LOG(DEBUG) << "Synthetic symbol " << synthetic_symbol->name << " "
               << std::hex << synthetic_symbol->start;
    out_symbols->emplace_back(std::move(synthetic_symbol));
  }
  std::sort(out_symbols->begin(), out_symbols->end(),
            [](const auto& a, const auto& b) { return *a < *b; });

  return true;
}

std::optional<std::pair<uint64_t, uint64_t>>
ELFFileDisassembler::GetExecutableSectionRangeContaining(uint64_t address) {
  return GetContainingRange(executable_section_ranges_, address);
}
