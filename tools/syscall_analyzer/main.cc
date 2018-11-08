/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <iostream>
#include <set>
#include <string>

#include <llvm/Support/CommandLine.h>

#include "logging.h"
#include "syscall_analyzer.h"

int main(int argc, char* argv[]) {
  llvm::cl::OptionCategory syscall_analyzer_category(
      "syscall_analyzer options");
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
    for (const std::string& symbol_name : symbol_names) {
      auto syscalls = syscall_analyzer->GetSyscallsCalledBy(symbol_name);
      if (!syscalls)
        return 1;

      std::cout << symbol_name << ":";
      for (int syscall : *syscalls)
        std::cout << " " << syscall;
      std::cout << "\n";
    }
  }
  return 0;
}
