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
#include "test_util.h"

namespace
{

class ConfigFileTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    list_ = new_config_entry_list();
  }
  virtual void TearDown() {
    free_config_entry_list(list_);
  }
  struct config_entry_list *list_;
};

} // namespace

TEST(ParsingConfigTest, valid_config_line) {
  auto *entry = (struct config_entry *)calloc(1, sizeof(struct config_entry));
  const std::vector<std::string> valid_conf_lines = {
      "mount=none",
      "binding = none",
      "  xyz = abc  ",
  };

  for (const auto conf_line : valid_conf_lines) {
    int ret = parse_config_line(conf_line.c_str(), entry);
    ASSERT_GE(ret, 0);
    free(entry->key);
    free(entry->value);
  }
  free(entry);
}

TEST(ParsingConfigTest, invalid_config_line) {
  auto *entry = (struct config_entry *)calloc(1, sizeof(struct config_entry));
  const std::vector<std::string> valid_conf_lines = {
      "mount=",
      "= none",
      "  malformed",
  };

  for (const auto conf_line : valid_conf_lines) {
    int ret = parse_config_line(conf_line.c_str(), entry);
    ASSERT_EQ(ret, -1);
  }
  free(entry);
}

TEST_F(ConfigFileTest, malformed) {
  std::string config = "malformed";
  FILE *config_file = write_to_pipe(config);
  ASSERT_NE(config_file, nullptr);

  int res = parse_config_file(config_file, list_);
  fclose(config_file);

  // Policy is malformed, but process should not crash.
  ASSERT_EQ(res, -1);
  ASSERT_EQ(list_->used, 0);
}

TEST_F(ConfigFileTest, wellformed_single_line) {
  std::string config = "# Comments \n"
           "\n"
           "mount = none\n"
           "binding = none,/tmp";
  FILE *config_file = write_to_pipe(config);
  ASSERT_NE(config_file, nullptr);

  int res = parse_config_file(config_file, list_);
  fclose(config_file);

  ASSERT_EQ(res, 0);
  ASSERT_EQ(list_->size, 2);
  ASSERT_EQ(list_->used, 2);
  struct config_entry *first_entry = list_->array;
  struct config_entry *second_entry = list_->array + 1;
  ASSERT_EQ(std::string(first_entry->key), "mount");
  ASSERT_EQ(std::string(first_entry->value), "none");
  ASSERT_EQ(std::string(second_entry->key), "binding");
  ASSERT_EQ(std::string(second_entry->value), "none,/tmp");
}

TEST_F(ConfigFileTest, wellformed_multi_line) {
  std::string config = "# Comments \n"
           "\n"
           "mount = \\\nnone\n"
           "binding = none,\\\n/tmp";
  FILE *config_file = write_to_pipe(config);
  ASSERT_NE(config_file, nullptr);

  int res = parse_config_file(config_file, list_);
  fclose(config_file);

  ASSERT_EQ(res, 0);
  ASSERT_EQ(list_->size, 2);
  ASSERT_EQ(list_->used, 2);
  struct config_entry *first_entry = list_->array;
  struct config_entry *second_entry = list_->array + 1;
  ASSERT_EQ(std::string(first_entry->key), "mount");
  ASSERT_EQ(std::string(first_entry->value), "none");
  ASSERT_EQ(std::string(second_entry->key), "binding");
  ASSERT_EQ(std::string(second_entry->value), "none, /tmp");
}