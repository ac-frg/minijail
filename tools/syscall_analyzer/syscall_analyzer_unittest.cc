/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/MemoryBuffer.h>

#include "disassembler.h"
#include "logging.h"
#include "syscall_analyzer.h"

namespace {

constexpr size_t kAlignment = 0x10;

struct InMemorySymbol {
  std::string name;
  std::vector<uint8_t> code;
};

class InMemoryDisassembler : public Disassembler {
 public:
  static std::unique_ptr<Disassembler> Create(
      std::string_view triple_name,
      std::vector<InMemorySymbol> in_memory_symbols) {
    std::vector<std::unique_ptr<SymbolInfo>> symbols;
    std::vector<uint8_t> buffer;
    for (const auto& in_memory_symbol : in_memory_symbols) {
      if (in_memory_symbol.code.size() % kAlignment != 0) {
        LOG(ERROR) << "Symbol " << in_memory_symbol.name
                   << " is not aligned to " << kAlignment << ". Size is "
                   << in_memory_symbol.code.size();
        return nullptr;
      }
      symbols.emplace_back(std::make_unique<SymbolInfo>(
          buffer.size(), buffer.size() + in_memory_symbol.code.size(),
          in_memory_symbol.name));
      buffer.insert(buffer.end(), in_memory_symbol.code.begin(),
                    in_memory_symbol.code.end());
    }

    std::unique_ptr<InMemoryDisassembler> disassembler(
        new InMemoryDisassembler(std::move(symbols), std::move(buffer)));
    if (!disassembler->CreateLLVMObjectsForTriple(
            llvm::Triple(llvm::Triple::normalize(triple_name.data())))) {
      return nullptr;
    }
    return disassembler;
  }

  virtual ~InMemoryDisassembler() = default;

  bool GetSymbols(
      std::vector<std::unique_ptr<SymbolInfo>>* out_symbols) override {
    *out_symbols = std::move(symbols_);
    return true;
  }
  std::optional<std::pair<uint64_t, uint64_t>>
  GetExecutableSectionRangeContaining(uint64_t address) override {
    if (address > buffer_.size())
      return std::nullopt;
    return std::make_optional(std::make_pair(0, buffer_.size()));
  }

 private:
  InMemoryDisassembler(std::vector<std::unique_ptr<SymbolInfo>> symbols,
                       std::vector<uint8_t> buffer)
      : symbols_(std::move(symbols)), buffer_(std::move(buffer)) {
    memory_buffer = llvm::MemoryBuffer::getMemBuffer(llvm::StringRef(
        reinterpret_cast<const char*>(buffer_.data()), buffer_.size()));
  }
  InMemoryDisassembler(InMemoryDisassembler&) = delete;
  InMemoryDisassembler& operator=(InMemoryDisassembler&) = delete;

  std::vector<std::unique_ptr<SymbolInfo>> symbols_;
  std::vector<uint8_t> buffer_;
};

TEST(Test, test_x86_64_control_flow_graph) {
  auto disassembler = InMemoryDisassembler::Create(
      "x86_64-pc-linux-gnu",
      {
          {
              "syscall",
              {
                  0x89, 0xf8,  // mov eax,edi
                  0x0f, 0x05,  // syscall
                  0xc3,        // ret
                  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
                  0x00,  // nop
                  0x90,  // nop
              },
          },
          {
              "notcalled",
              {
                  0xbf, 0x04, 0x00, 0x00, 0x00,  // mov edi,0x4
                  0xeb, 0xe9,                    // jmp <syscall>
                  0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,  // nop
              },
          },
          {
              "exit",
              {
                  0x50,                          // push rax
                  0xbf, 0x03, 0x00, 0x00, 0x00,  // mov edi,0x3
                  0xe8, 0xd5, 0xff, 0xff, 0xff,  // call <syscall>
                  0x0f, 0x1f, 0x44, 0x00, 0x00,  // nop
              },
          },
          {
              "main",
              {
                  0x50,                          // push rax
                  0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax,0x1
                  0x0f, 0x05,                    // syscall
                  0xbf, 0x02, 0x00, 0x00, 0x00,  // mov edi,0x2
                  0xe8, 0xbe, 0xff, 0xff, 0xff,  // call <syscall>
                  0xe8, 0xd9, 0xff, 0xff, 0xff,  // call <exit>
                  0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,  // nop
              },
          },
      });
  ASSERT_NE(disassembler.get(), nullptr);

  auto syscall_analyzer = SyscallAnalyzer::Create(std::move(disassembler));
  ASSERT_NE(syscall_analyzer.get(), nullptr);

  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("syscall"),
            std::make_optional(std::set<int>{}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("notcalled"),
            std::make_optional(std::set<int>{4}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("exit"),
            std::make_optional(std::set<int>{3}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("main"),
            std::make_optional(std::set<int>{1, 2, 3}));
}

TEST(Test, test_x86_control_flow_graph) {
  auto disassembler = InMemoryDisassembler::Create(
      "i686-pc-linux-gnu",
      {
          {
              "syscall",
              {
                  0x8b, 0x44, 0x24, 0x04,  // mov eax,DWORD PTR[esp+0x4]
                  0xcd, 0x80,              // int 0x80
                  0xc3,                    // ret
                  0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,  // nop
              },
          },
          {
              "notcalled",
              {
                  0x83, 0xec, 0x08,              // sub esp,0x8
                  0x6a, 0x04,                    // push 0x4
                  0xe8, 0xe6, 0xff, 0xff, 0xff,  // call <syscall>
                  0x83, 0xc4, 0x0c,              // add esp,0xc
                  0xc3,                          // ret
                  0x66, 0x90,                    // nop
              },
          },
          {
              "exit",
              {
                  0x83, 0xec, 0x0c,  // sub esp,0xc
                  0xc7, 0x04, 0x24, 0x03, 0x00, 0x00,
                  0x00,                          // mov DWORD PTR[esp],0x3
                  0xe8, 0xd1, 0xff, 0xff, 0xff,  // call <syscall>
                  0x83, 0xec, 0x04,              // sub esp,0x4
                  0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
                  0x00,                    // nop
                  0x0f, 0x1f, 0x40, 0x00,  // nop
              },
          },
          {
              "main",
              {
                  0x83, 0xec, 0x0c,              // sub esp,0xc
                  0xb8, 0x01, 0x00, 0x00, 0x00,  // mov eax,0x1
                  0xcd, 0x80,                    // int 0x80
                  0xc7, 0x04, 0x24, 0x02, 0x00, 0x00,
                  0x00,                          // mov DWORD PTR[esp],0x2
                  0xe8, 0xaa, 0xff, 0xff, 0xff,  // call <syscall>
                  0xe8, 0xc5, 0xff, 0xff, 0xff,  // call <exit>
                  0x0f, 0x1f, 0x40, 0x00,        // nop
                  0x90,                          // nop
              },
          },
      });
  ASSERT_NE(disassembler.get(), nullptr);

  auto syscall_analyzer = SyscallAnalyzer::Create(std::move(disassembler));
  ASSERT_NE(syscall_analyzer.get(), nullptr);

  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("syscall"),
            std::make_optional(std::set<int>{}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("notcalled"),
            std::make_optional(std::set<int>{4}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("exit"),
            std::make_optional(std::set<int>{3}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("main"),
            std::make_optional(std::set<int>{1, 2, 3}));
}

TEST(Test, test_aarch64_control_flow_graph) {
  auto disassembler = InMemoryDisassembler::Create(
      "aarch64-pc-linux-gnu",
      {
          {
              "syscall",
              {
                  0xe8, 0x03, 0x00, 0x2a,  // mov w8, w0
                  0x01, 0x00, 0x00, 0xd4,  // svc #0
                  0xc0, 0x03, 0x5f, 0xd6,  // ret
                  0x1f, 0x20, 0x03, 0xd5,  // nop
              },
          },
          {
              "notcalled",
              {
                  0x80, 0x00, 0x80, 0xd2,  // mov x0, #4
                  0xfb, 0xff, 0xff, 0x17,  // b   #-20
                  0x1f, 0x20, 0x03, 0xd5,  // nop
                  0x1f, 0x20, 0x03, 0xd5,  // nop
              },
          },
          {
              "exit",
              {
                  0xfd, 0x7b, 0xbf, 0xa9,  // stp x29, x30, [sp, #-16]!
                  0x60, 0x00, 0x80, 0x52,  // mov w0, #3
                  0xfd, 0x03, 0x00, 0x91,  // mov x29, sp
                  0xf5, 0xff, 0xff, 0x97,  // bl  #-44
              },
          },
          {
              "main",
              {
                  0xfd, 0x7b, 0xbf, 0xa9,  // stp x29, x30, [sp, #-16]!
                  0xe8, 0x03, 0x00, 0x32,  // orr w8, wzr, #1
                  0xfd, 0x03, 0x00, 0x91,  // mov x29, sp
                  0x01, 0x00, 0x00, 0xd4,  // svc #0
                  0x40, 0x00, 0x80, 0x52,  // mov w0, #2
                  0xef, 0xff, 0xff, 0x97,  // bl  #-68
                  0xf6, 0xff, 0xff, 0x97,  // bl  #-40
                  0x1f, 0x20, 0x03, 0xd5,  // nop
              },
          },
      });
  ASSERT_NE(disassembler.get(), nullptr);

  auto syscall_analyzer = SyscallAnalyzer::Create(std::move(disassembler));
  ASSERT_NE(syscall_analyzer.get(), nullptr);

  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("syscall"),
            std::make_optional(std::set<int>{}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("notcalled"),
            std::make_optional(std::set<int>{4}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("exit"),
            std::make_optional(std::set<int>{3}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("main"),
            std::make_optional(std::set<int>{1, 2, 3}));
}

TEST(Test, test_arm_control_flow_graph) {
  auto disassembler = InMemoryDisassembler::Create(
      "arm-pc-linux-gnu",
      {
          {
              "syscall",
              {
                  0x04, 0x70, 0x2d, 0xe5,  // str r7, [sp, #-4]!
                  0x00, 0x70, 0xa0, 0xe1,  // mov r7, r0
                  0x00, 0x00, 0x00, 0xef,  // svc #0
                  0x04, 0x70, 0x9d, 0xe4,  // ldr r7, [sp], #4
                  0x1e, 0xff, 0x2f, 0xe1,  // bx  lr
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
              },
          },
          {
              "notcalled",
              {
                  0x04, 0x00, 0xa0, 0xe3,  // mov r0, #4
                  0xf5, 0xff, 0xff, 0xea,  // b   #-44 <syscall>
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
              },
          },
          {
              "exit",
              {
                  0x10, 0x40, 0x2d, 0xe9,  // push{r4, lr}
                  0x03, 0x00, 0xa0, 0xe3,  // mov r0, #3
                  0xf0, 0xff, 0xff, 0xeb,  // bl  #-64 <syscall>
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
              },
          },
          {
              "main",
              {
                  0x80, 0x40, 0x2d, 0xe9,  // push{r7, lr}
                  0x01, 0x70, 0xa0, 0xe3,  // mov r7, #1
                  0x00, 0x00, 0x00, 0xef,  // svc #0
                  0x02, 0x00, 0xa0, 0xe3,  // mov r0, #2
                  0xea, 0xff, 0xff, 0xeb,  // bl  #-8 <main+0x10>
                  0xf5, 0xff, 0xff, 0xeb,  // bl  #-8 <main+0x14>
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
                  0x00, 0x00, 0xa0, 0xe1,  // mov r0, r0
              },
          },
      });
  ASSERT_NE(disassembler.get(), nullptr);

  auto syscall_analyzer = SyscallAnalyzer::Create(std::move(disassembler));
  ASSERT_NE(syscall_analyzer.get(), nullptr);

  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("syscall"),
            std::make_optional(std::set<int>{}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("notcalled"),
            std::make_optional(std::set<int>{4}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("exit"),
            std::make_optional(std::set<int>{3}));
  ASSERT_EQ(syscall_analyzer->GetSyscallsTransitivelyCalledBy("main"),
            std::make_optional(std::set<int>{1, 2, 3}));
}

}  // namespace
