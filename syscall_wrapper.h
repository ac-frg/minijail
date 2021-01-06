/* Copyright 2016 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef _SYSCALL_WRAPPER_H_
#define _SYSCALL_WRAPPER_H_

#include "bpf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Seccomp filter related flags. */
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2 /* Uses user-supplied filter. */
#endif

#ifndef SECCOMP_SET_MODE_STRICT
# define SECCOMP_SET_MODE_STRICT 0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
# define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
# define SECCOMP_FILTER_FLAG_TSYNC 1
#endif

#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
# define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1 << 2)
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
# define SECCOMP_FILTER_FLAG_NEW_LISTENER (1 << 3)
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
# define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1 << 4)
#endif
/* End seccomp filter related flags. */

/*
 * Macros and flags for seccomp notification fd ioctl. From
 * include/uapi/linux/seccomp.h
 */
#define SECCOMP_IOC_MAGIC   '!'
#define SECCOMP_IO(nr)      _IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type)   _IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type)   _IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type)    _IOWR(SECCOMP_IOC_MAGIC, nr, type)

#define SECCOMP_IOCTL_NOTIF_RECV  SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND  SECCOMP_IOWR(1, \
                struct seccomp_notif_resp)

int sys_seccomp(unsigned int operation, unsigned int flags, void *args);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* _SYSCALL_WRAPPER_H_ */
