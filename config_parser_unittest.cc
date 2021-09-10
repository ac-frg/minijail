/* Copyright 2021 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test config_parser.c using gtest.
 */

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h> /* For O_WRONLY. */

#include <gtest/gtest.h>
#include <string>

#include "config_parser.h"
#include "util.h"

namespace
{

class ConfigFileTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    head_ = new_config_entry();
  }
  virtual void TearDown() {
    free_config_entry_list(head_);
    free(head_);
  }
  struct config_entry *head_;
};

} // namespace

TEST(ParsingConfigTest, valid_config_line) {
  struct config_entry *entry;
  const std::vector<std::string> valid_conf_lines = {
      "mount=none",
      "binding = none",
      "  xyz = abc  ",
  };

  for (const auto conf_line : valid_conf_lines) {
    entry = parse_config_line(conf_line.c_str());
    ASSERT_NE(entry, nullptr);
    free(entry);
  }
}

TEST(ParsingConfigTest, invalid_config_line) {
  struct config_entry *entry;
  const std::vector<std::string> valid_conf_lines = {
      "mount=",
      "= none",
      "  malformed",
  };

  for (const auto conf_line : valid_conf_lines) {
    entry = parse_config_line(conf_line.c_str());
    ASSERT_EQ(entry, nullptr);
  }
}

TEST_F(ConfigFileTest, malformed) {
  std::string config = "malformed";
  FILE *config_file = write_to_pipe(config.c_str());
  ASSERT_NE(config_file, nullptr);

  int res = parse_config_file(config_file, head_);
  fclose(config_file);

  // Policy is malformed, but process should not crash.
  ASSERT_EQ(res, -1);
  ASSERT_EQ(head_->list_len, 0);
}

TEST_F(ConfigFileTest, wellformed) {
  std::string config = "# Comments \n"
           "\n"
           "mount = none\n"
           "binding = none,/tmp";
  FILE *config_file = write_to_pipe(config.c_str());
  ASSERT_NE(config_file, nullptr);

  int res = parse_config_file(config_file, head_);
  fclose(config_file);

  ASSERT_EQ(res, 0);
  ASSERT_EQ(head_->list_len, 2);
  struct config_entry *first_entry = head_->next;
  struct config_entry *second_entry = head_->next->next;
  ASSERT_EQ(std::string(first_entry->key), "binding");
  ASSERT_EQ(std::string(first_entry->value), "none,/tmp");
  ASSERT_EQ(std::string(second_entry->key), "mount");
  ASSERT_EQ(std::string(second_entry->value), "none");
}