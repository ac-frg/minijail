#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
constexpr char kProcSelfStatus[] = "/proc/self/status";
}

int main(void) {
  int should_fail = open(kProcSelfStatus, O_RDONLY);

  if (should_fail >= 0) {
    fprintf(stderr, "Seccomp failed to block open call without O_CLOEXEC\n");
    close(should_fail);
    return 1;
  }

  if (should_fail == -1) {
    if (errno != 1) {
      fprintf(stderr, "Seccomp failed to return EPERM on open call "
                      "without O_CLOEXEC\n");
    }
  }

  int should_succeed = open(kProcSelfStatus, O_RDONLY | O_CLOEXEC);

  if (should_succeed < 0) {
    perror("open(/proc/self/status, O_RDONLY|O_CLOEXEC) failed");
    return 1;
  }

  // Try to mmap something W+X.

  // Try to call prctl.

  // Try to do an ioctl.

  return 0;
}
