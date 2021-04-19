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

#include "sanitizer_watchaddr.h"
#include "sanitizer_internal_defs.h"
#include "sanitizer_stacktrace.h"
//#include "asan/asan_allocator.h"
//#include "asan/asan_mapping.h"



namespace __sanitizer {

    // The hard limit on number of distinct leaks that can be reported by LSAN
    const int kMaxWatchAddr=5000;

    // AVL tree mapping id to LastUse StackTrace
    //avl_array<u32,BufferedStackTrace*, std::uint32_t, 5000, true> avl;
    avl_array<u32,BufferedStackTrace*, int, 5000, true> avl;
    BufferedStackTrace bs[5000];

    // Copy BufferedStackTrace from source to destination pointer
    void CopyBufferedStackTrace(BufferedStackTrace* dest, BufferedStackTrace* source)
    {
        dest->size = source->size;
        dest->tag = source->tag;
        dest->top_frame_bp = source->top_frame_bp;

        for (int i=0;i<dest->size;i++)
            dest->trace_buffer[i] = source->trace_buffer[i];

        return;
    }

    bool StackDepotPutLastUse(u32 id, BufferedStackTrace* s)
    {
        BufferedStackTrace* bsend = &(bs[avl.size()]);

        auto it = avl.insertwithoutupdate(id,bsend);

        // AVL tree filled upto capacity
        if (it == avl.end())
            return false;

        // id already exists, update stacktrace
        if (*it != bsend)
        {
            CopyBufferedStackTrace(*it,s);
            return true;
        }

        // id is new, update the stacktrace
        CopyBufferedStackTrace(bsend,s);
        return true;
    }

    void StackDepotPrintLastUse(u32 id)
    {
        auto it = avl.find(id);

        if (it != avl.end())
        {
            (*it)->Print();
        }

        return;
    }

    BufferedStackTrace* StackDepotGetLastUse(u32 id)
    {
        auto it = avl.find(id);

        if (it != avl.end())
        {
            return *it;
        }

        return nullptr;
    }
}

//namespace __asan {

    // Find If address in ptr is actually watched memory. If so Update last use
    // for this chunk of watched memory.
//    void UpdateLastUseForWatchedChunk(uptr ptr, BufferedStackTrace* s)
//    {
//        AsanChunkView chunk = FindHeapChunkByAddress(ptr);
//        StackDepotPutLastUse(chunk.GetAllocStackId(),s);
//        return;
//    }

    // Identiifies if a given memory chunk contains pointers to a watched memory region
    // If so we update last use for the watched chunk
    //bool TrackPointersToWatchedMemory(void* ptr,uptr size, BufferedStackTrace* s) {

//        int** copy = (int**)ptr;
 
        // Printf("The ptr : %d , and value is : %d \n",ptr,*(u8*)MemToShadow((uptr)copy));

//        u8* shadowptr = (u8*)MemToShadow((uptr)copy);

//        for (uptr i=0; i <= size-sizeof(int*);i++)
//        {
//            uptr value = (uptr)*copy;

            // Printf("The memory: %d, the value %d, \n",copy,value);
//            if (AddrIsInMem(value))
//            {
//                u8* shadowvalue = (u8 *)MemToShadow(value);
                // Printf(" the shadowvalue %d \n",*shadowvalue);

//                if ((*shadowvalue & 0xe0) == 0xe0)
//                    UpdateLastUseForWatchedChunk(value,s);
//            }

//            copy = (int**)((char*)copy + 1);
//        }
//        return false;
//    }
//}
