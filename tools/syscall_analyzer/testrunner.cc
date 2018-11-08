/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Main entrypoint for gtest.
 */

#include <stdio.h>
#include <stdlib.h>

#include <gtest/gtest.h>

#include "disassembler.h"
#include "logging.h"

namespace {

class Environment : public ::testing::Environment {
 public:
  ~Environment() override = default;

  void SetUp() override {
    logging::Init(STDERR_FILENO, getenv("VERBOSE") ? DEBUG : INFO);
    Disassembler::InitLLVM();
  }
};

}  // namespace

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  ::testing::AddGlobalTestEnvironment(new Environment());
  return RUN_ALL_TESTS();
}
