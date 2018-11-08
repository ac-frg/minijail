/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <iostream>
#include <queue>
#include <set>
#include <string>

#include <llvm/Support/CommandLine.h>

#include "logging.h"
#include "syscall_analyzer.h"

int main(int argc, char* argv[]) {
  llvm::cl::OptionCategory syscall_analyzer_category(
      "syscall_analyzer options");
  llvm::cl::opt<bool> dot(
      "dot", llvm::cl::desc("Output a graph of called syscalls in DOT format"),
      llvm::cl::cat(syscall_analyzer_category));
  llvm::cl::opt<bool> verbose("verbose", llvm::cl::desc("Display verbose logs"),
                              llvm::cl::cat(syscall_analyzer_category));
  llvm::cl::alias verbose_short("v", llvm::cl::desc("Alias for --verbose"),
                                llvm::cl::aliasopt(verbose),
                                llvm::cl::cat(syscall_analyzer_category));
  llvm::cl::list<std::string> input_filenames(
      llvm::cl::Positional, llvm::cl::desc("<input object files>"),
      llvm::cl::OneOrMore, llvm::cl::cat(syscall_analyzer_category));
  llvm::cl::list<std::string> functions(
      "functions", llvm::cl::CommaSeparated,
      llvm::cl::desc("List of functions to display"),
      llvm::cl::cat(syscall_analyzer_category));

  llvm::cl::HideUnrelatedOptions(syscall_analyzer_category);
  llvm::cl::ParseCommandLineOptions(argc, argv, "syscall analyzer\n");

  if (input_filenames.empty()) {
    llvm::cl::PrintHelpMessage();
    return 1;
  }

  logging::Init(2, verbose ? DEBUG : INFO);

  SyscallAnalyzer::InitLLVM();

  for (const std::string& filename : input_filenames) {
    auto syscall_analyzer = SyscallAnalyzer::OpenFile(filename);
    if (!syscall_analyzer)
      return 1;
    std::set<std::string> symbol_names;
    if (functions.empty())
      symbol_names = syscall_analyzer->GetSymbolNames();
    else
      symbol_names.insert(functions.begin(), functions.end());
    if (dot) {
      std::cout << "digraph {\n";
      std::set<BasicBlock*> visited;
      std::queue<BasicBlock*> q;
      for (const std::string& symbol_name : symbol_names) {
        auto block = syscall_analyzer->GetBasicBlock(symbol_name);
        if (!block)
          return 1;
        q.emplace(*block);
      }
      while (!q.empty()) {
        BasicBlock* block = q.front();
        q.pop();
        if (!visited.insert(block).second)
          continue;

        auto report = syscall_analyzer->GetSyscallReportFor(block);
        if (!report)
          return 1;

        std::cout << "  subgraph {\n";
        std::cout << "  \"" << ShortDescription(block) << "\" [shape=box];";
        for (int syscall : report->direct_syscalls) {
          std::cout << "    \"" << ShortDescription(block) << "_syscall_"
                    << std::dec << syscall << "\" [label=\"" << std::dec
                    << syscall << "\"];\n";
          std::cout << "    \"" << ShortDescription(block) << "\" -> \""
                    << ShortDescription(block) << "_syscall_" << std::dec
                    << syscall << "\";\n";
        }
        std::cout << "  }\n";
        for (BasicBlock* child : report->called_functions) {
          std::cout << "  \"" << ShortDescription(block) << "\" -> \""
                    << ShortDescription(child) << "\";\n";
          q.push(child);
        }
      }
      std::cout << "}\n";
    } else {
      for (const std::string& symbol_name : symbol_names) {
        auto syscalls =
            syscall_analyzer->GetSyscallsTransitivelyCalledBy(symbol_name);
        if (!syscalls)
          return 1;

        std::cout << symbol_name << ":";
        for (int syscall : *syscalls)
          std::cout << " " << syscall;
        std::cout << "\n";
      }
    }
  }
  return 0;
}
