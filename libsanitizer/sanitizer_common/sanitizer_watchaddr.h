//===-- sanitizer_watchaddr.h ----------------------------------*- C++ -*-===//
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
#include "sanitizer_internal_defs.h"
#include "sanitizer_stacktrace.h"
#include "sanitizer_checkwatchavl.h"

namespace __sanitizer {

    //extern avl_array<u32,BufferedStackTrace*, std::uint32_t, 5000, true> avl;
    extern avl_array<u32,BufferedStackTrace*, int, 5000, true> avl;
    extern BufferedStackTrace bs[5000];

    bool StackDepotPutLastUse(u32 id, BufferedStackTrace* s);
    void StackDepotPrintLastUse(u32 id);
    BufferedStackTrace* StackDepotGetLastUse(u32 id);
}


//namespace __asan {
//    void UpdateLastUseForWatchedChunk(uptr ptr, BufferedStackTrace* s);
//    bool TrackPointersToWatchedMemory(void* ptr,uptr size, BufferedStackTrace* s);
//}
