/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#if !defined(LOGGING_H_)
#define LOGGING_H_

#include <errno.h>

#include <cstring>
#include <optional>
#include <ostream>
#include <sstream>

enum LogLevel : uint32_t { DEBUG, INFO, WARN, ERROR, FATAL };

std::ostream& operator<<(std::ostream& o, LogLevel level);

#define LOG(level) logging::ScopedLogger(level, __FILE__, __LINE__)
#define PLOG(level) logging::ScopedLogger(level, __FILE__, __LINE__, errno)

namespace logging {

void Init(int fd, LogLevel min_log_level);

class ScopedLogger : std::ostream {
 public:
  ScopedLogger(LogLevel level,
               const char* file_path,
               size_t line,
               std::optional<int> current_errno = std::nullopt);
  ~ScopedLogger();

  template <typename T>
  std::ostream& operator<<(const T& t) {
    return buffer_ << t;
  }

 private:
  const LogLevel level_;
  const std::optional<int> current_errno_;
  std::ostringstream buffer_;
};

}  // namespace logging

#endif  // LOGGING_H_
