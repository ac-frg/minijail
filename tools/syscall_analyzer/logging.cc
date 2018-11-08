/* Copyright (c) 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "logging.h"

#include <sys/time.h>
#include <unistd.h>

#include <iomanip>

// Used to explicitly mark the return value of a function as unused. If you are
// really sure you don't want to do anything with the return value of a function
// that has been marked WARN_UNUSED_RESULT, wrap it with this. Example:
//
//   std::unique_ptr<MyType> my_var = ...;
//   if (TakeOwnership(my_var.get()) == SUCCESS)
//     ignore_result(my_var.release());
//
template <typename T>
inline void ignore_result(const T&) {}

std::ostream& operator<<(std::ostream& o, LogLevel level) {
  switch (level) {
    case LogLevel::DEBUG:
      return o << "DBUG";
    case LogLevel::INFO:
      return o << "INFO";
    case LogLevel::WARN:
      return o << "WARN";
    case LogLevel::ERROR:
      return o << "EROR";
    case LogLevel::FATAL:
      return o << "FATL";
  }

  return o;
}

namespace logging {

namespace {

int g_logging_fd = 2;
LogLevel g_min_log_level = INFO;

}  // namespace

void Init(int fd, LogLevel min_log_level) {
  g_logging_fd = fd;
  g_min_log_level = min_log_level;
}

ScopedLogger::ScopedLogger(LogLevel level,
                           const char* file_path,
                           size_t line,
                           std::optional<int> current_errno)
    : level_(level), current_errno_(std::move(current_errno)) {
  timeval tv;
  gettimeofday(&tv, nullptr);
  time_t t = tv.tv_sec;
  struct tm local_time;
  localtime_r(&t, &local_time);
  struct tm* tm_time = &local_time;
  *this << "[" << level << " ";
  *this << std::setfill('0') << std::setw(4) << (1900 + tm_time->tm_year) << "-"
        << std::setw(2) << (1 + tm_time->tm_mon) << "-" << std::setw(2)
        << tm_time->tm_mday << "T" << std::setw(2) << tm_time->tm_hour << ":"
        << std::setw(2) << tm_time->tm_min << ":" << std::setw(2)
        << tm_time->tm_sec << "." << std::setw(6) << tv.tv_usec;
  const char* filename = strrchr(file_path, '/');
  if (filename)
    ++filename;  // Skip the last slash.
  else
    filename = file_path;
  *this << " " << filename << "(" << line << ")] ";
}

ScopedLogger::~ScopedLogger() {
  if (current_errno_) {
    char error_str[128];
    if (strerror_r(*current_errno_, error_str, sizeof(error_str)) != 0) {
      snprintf(error_str, sizeof(error_str), "errno=%d", *current_errno_);
    }
    *this << ": " << error_str;
  }
  buffer_ << "\n";

  if (g_logging_fd != -1 && level_ >= g_min_log_level) {
    const std::string str = buffer_.str();
    // Perform best-effort writing into the log file.
    ignore_result(::write(g_logging_fd, str.c_str(), str.size()));
  }

  if (level_ == LogLevel::FATAL)
    abort();
}

}  // namespace logging
