/* signal_handler.h
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Signal handling functions.
 */

#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

/*
 * SIGUNUSED for MIPS. Other architectures define SIGUNUSED as the last valid
 * signal (by number), so do the same for MIPS.
 * See http://elixir.free-electrons.com/linux/v4.4.68/source/arch/mips/include/uapi/asm/signal.h#L57
 */
#if defined(__mips__)
#if !defined(SIGUNUSED)
#define SIGUNUSED 31
#endif
#endif

int install_sigsys_handler();

#endif /* SIGNAL_HANDLER_H */
