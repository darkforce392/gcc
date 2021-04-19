//===-- sanitizer_watchaddrfileio.h ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between all the Sanitizer
// run-time libraries.
//===----------------------------------------------------------------------===//

#include "sanitizer_common.h"
#include "sanitizer_stacktrace.h"

namespace __sanitizer {

    class AddrWatch;
    extern AddrWatch addrwatch;

    bool IsAddrToWatch(BufferedStackTrace* s);
    uptr CheckIfBinaryRecompiled(uptr time);
    void InitializeWatchlist();
    void UpdateWatchlist(StackTrace* mallocstack, BufferedStackTrace* lastusethisrun);
}
