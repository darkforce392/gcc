//===-- sanitizer_watchaddrfileio.cpp ----------------------------------*- C++ -*-===//
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
#include "sanitizer_watchaddrfileio.h"

namespace __sanitizer {

    bool inline WriteUptr(uptr x)
    {
        char c[sizeof(uptr)*2+2];
        c[sizeof(uptr)*2]='\n';
        c[sizeof(uptr)*2+1]='\0';

        int j = sizeof(uptr)*2-1;
        for (int i=0;i<sizeof(uptr)*2;i++)
        {
            c[j]= (x & 0xf) + 48;

            if (c[j]>=58)
               c[j]=c[j]+39;

            x=(x>>4);
            j--;
        }

        WatchAddrRawWrite(c);
        return true;
    }

    bool WriteWatchAddr(StackTrace* s)
    {
        // Can be used when there is no last use during a run
        if (s == nullptr)
        {
            WriteUptr(0);
            return true;
        }

        WriteUptr(s->size);

        for (int i=0; i<(s->size); i++)
        {
            WriteUptr(s->trace[i]);
        }
        return true;
    }
    
    bool WriteWatchAddr(BufferedStackTrace* s)
    {
        // Can be used when there is no last use during a run
        if (s == nullptr)
        {
            WriteUptr(0);
            return true;
        }

        WriteUptr(s->size);

        for (int i=0; i<(s->size); i++)
        {
            WriteUptr(s->trace_buffer[i]);
        }
        return true;
    }

    class AddrWatch {

    public:

        const static int maxwatch = 5000;
        BufferedStackTrace watchstack[maxwatch];
        BufferedStackTrace lastusestack[maxwatch];
        BufferedStackTrace* sortedstack[maxwatch];
        bool foundthisrun[maxwatch] = {false};
        int bspos = 0;

        BufferedStackTrace* GetLastUseStack(int pos) {
            return &(lastusestack[pos]);
        }

        BufferedStackTrace* GetStack(int pos) {
            return &(watchstack[pos]);
        }

        BufferedStackTrace* InsertNewStack() {
            return GetStack(bspos++);
        }

        int GetSize(){
            return bspos;
        }

        void SetStackWrittenToWatchlist(int pos) {
            foundthisrun[pos]=1;
        }


        AddrWatch() {
        }

        ~AddrWatch() {

            // Write Malloc stacks that were not found in this run to Address Watcher Watchlist
            for (int i=0; i<bspos; i++)
                if (foundthisrun[i] == false)
                {
                    WriteWatchAddr(&watchstack[i]);
                    WriteWatchAddr(&lastusestack[i]);
                }

        }

        bool static CompareBufferedStackTrace(BufferedStackTrace* x, BufferedStackTrace* y);
        bool static CompareStackTrace(StackTrace* x, BufferedStackTrace* y);
        bool static EqualBufferedStackTrace(BufferedStackTrace* x, BufferedStackTrace* y);
        bool static EqualBufferedStackTrace(StackTrace* x, BufferedStackTrace* y);
        void InitandSort();
        uptr inline ReadUptr(char** c);
        void inline ReadStack(BufferedStackTrace* s, char** c);
        bool ReadWatchAddr();
        int IsStackPresent(BufferedStackTrace* s);
        int IsStackPresent(StackTrace* s);
    };

    AddrWatch addrwatch;

    bool AddrWatch::EqualBufferedStackTrace (BufferedStackTrace* x, BufferedStackTrace* y)
    {
        if (x->size != y->size)
           return false;

        // Discard top and bottom line
        for (int i=1;i<(x->size)-1;i++)
            if (x->trace_buffer[i] != y->trace_buffer[i])
                return false;

        return true;
    }

    bool AddrWatch::EqualBufferedStackTrace (StackTrace* x, BufferedStackTrace* y)
    {
        if (x->size != y->size)
           return false;

        // Discard top and bottom line
        for (int i=1;i<(x->size)-1;i++)
            if (x->trace[i] != y->trace_buffer[i])
                return false;

        return true;
    }

    bool AddrWatch::CompareBufferedStackTrace(BufferedStackTrace* x, BufferedStackTrace* y)
    {
        if (x->size < y->size)
            return true;

        if (x->size > y->size)
            return false;

        // Discard top and bottom line
        for(int i=1; i<(x->size)-1 ;i++)
        {
            if (x->trace_buffer[i] == y->trace_buffer[i])
                continue;

            if (x->trace_buffer[i] < y->trace_buffer[i])
                return true;

            // x Greater
            return false;
        }

        // Equal Stacktraces. No need to swap
        return true;
    }

    bool AddrWatch::CompareStackTrace(StackTrace* x, BufferedStackTrace* y)
    {
        if (x->size < y->size)
            return true;

        if (x->size > y->size)
            return false;

        // Discard top and bottom line
        for(int i=1; i<(x->size)-1 ;i++)
        {
            if (x->trace[i] == y->trace_buffer[i])
                continue;

            if (x->trace[i] < y->trace_buffer[i])
                return true;

            // x Greater
            return false;
        }

        // Equal Stacktraces. No need to swap
        return true;
    }


    // Binary Search our list of StackTrace pointers
    int AddrWatch::IsStackPresent(BufferedStackTrace* s)
    {
        int high = GetSize()-1;
        int low = 0;
        
        while (high >= low)
        {
            int mid = (high+low)/2;
            BufferedStackTrace* midstack = sortedstack[mid];

            if (EqualBufferedStackTrace(s,midstack))
               return mid;
            else if (CompareBufferedStackTrace(s,midstack))
                high = mid-1;
            else
                low = mid+1;

        }
        return -1;
    }

    // Binary Search our list of StackTrace pointers
    int AddrWatch::IsStackPresent(StackTrace* s)
    {
        int high = GetSize()-1;
        int low = 0;
        
        while (high >= low)
        {
            int mid = (high+low)/2;
            BufferedStackTrace* midstack = sortedstack[mid];

            if (EqualBufferedStackTrace(s,midstack))
                return mid;
            else if (CompareStackTrace(s,midstack))
                high = mid-1;
            else
                low = mid+1;

        }
        return -1;
    }

    void AddrWatch::InitandSort()
    {
        for(int i=0; i<bspos; i++)
            sortedstack[i] = GetStack(i);

        Sort(sortedstack,(uptr)bspos,CompareBufferedStackTrace);
    }

    uptr inline AddrWatch::ReadUptr(char** c)
    {
        uptr res=0;
        for (int j = 0; j <= sizeof(uptr)*2-1; j++)
        {
            int val=((*c)[j] & 0xff);

            if (val>=97)
                val=val-87;
            else
                val=val-48;

            res =res | val;

            if (j != sizeof(uptr)*2-1)
                res = res<<4;
        }

        // There is also a new line here which we dont care to take in
        *c=*c+sizeof(uptr)*2+1;
        return res;
    }

    void inline AddrWatch::ReadStack(BufferedStackTrace* s, char** c)
    {
        s->size = ReadUptr(c);

        for (uptr k=0;k<s->size;k++)
        {
            s->trace_buffer[k] = ReadUptr(c);
        }
    }

    bool AddrWatch::ReadWatchAddr()
    {
        char* c;
        uptr csize = 0;
        uptr read_len = 0;
        // The maximum bytes to read from our Address Watcher report.
        // This value is calculated from the maximum number of malloc stacks we're allowed to track
        // Multiplying by 2: for each malloc stack, there is a last use stack
        // Each line of a stack has 16 bytes
        // Every stack has a maximum of kStackTraceMax +1 lines including the length header.
        // We add 1 finally for the first line of the report: last built time for the binary.
        uptr max_len = (maxwatch*2*(12+1)*16)+1;
        bool opened = ReadAddrReportToBuffer(&c,&csize,&read_len,max_len);

        // If not created write the correct compile date and sign off 
        if (!opened)
            return false;

        char* p=c;

        uptr compile_time = ReadUptr(&p);
 
        // If Binary recompiled don't read this data!!
        if (CheckIfBinaryRecompiled(compile_time))
            return false;

        int scannedstacks=0;
        while (*p)
        {
            BufferedStackTrace* s = this->InsertNewStack();
            ReadStack(s,&p);

            BufferedStackTrace* ls = this->GetLastUseStack(scannedstacks);
            ReadStack(ls,&p);
            scannedstacks++;
        }
        return true;
    }

    uptr CheckIfBinaryRecompiled(uptr time)
    {
        static uptr storedcompiletime = 0;

        if (time>=storedcompiletime)
        {
            storedcompiletime=time;
            return 0;
        }

        return storedcompiletime;
    }

    void InitializeWatchlist()
    {
        static bool time_stamp_written_to_report = 0;

        // Read addresses to watch from file
        if (addrwatch.ReadWatchAddr())
        {
            // Create sorted array of stacktraces through pointers
            addrwatch.InitandSort();
        }

        // Write the correct compile time for successive binary runs.
        if (time_stamp_written_to_report == 0)
        {
           time_stamp_written_to_report = 1;
           WriteUptr(CheckIfBinaryRecompiled(0));
        }
    }

    bool IsAddrToWatch(BufferedStackTrace *s)
    {
        int pos = addrwatch.IsStackPresent(s); 
        if (pos == -1)
            return false;

        // Mark this stack as found during this run.
        // We will be writing the malloc stack through LeakSanitizer report
        // We don't want to write it to watchlist again.
        addrwatch.SetStackWrittenToWatchlist(pos);
        return true;
    }

    BufferedStackTrace* MergeLastUse(BufferedStackTrace* x, BufferedStackTrace* y)
    {
        if ((x != nullptr) && (x->size<2))
            x=nullptr;

        if ((y != nullptr) && (y->size<2))
            y=nullptr;


        if ((x == nullptr) && (y==nullptr))
            return nullptr;

        if (x==nullptr)
            return y;

        if (y==nullptr)
            return x;

        int xbottom = x->size-2;
        int ybottom = y->size-2;

        while ((xbottom >= 0) && (ybottom >= 0))
        {
            if (x->trace_buffer[xbottom] > y->trace_buffer[ybottom])
            {
                return x;
            }

            if (x->trace_buffer[xbottom] < y->trace_buffer[ybottom])
            {
                return y;
            }

            xbottom--;
            ybottom--;
        }

        // At this point both stacks are equal
        return x;
    }

    void UpdateWatchlist(StackTrace* mallocstack, BufferedStackTrace* lastusethisrun)
    {
        // First write the malloc stack as is to Watchlist
        WriteWatchAddr(mallocstack);

        // Last use over all previous runs. We have already read this info from the watchlist.
        // Accessing this now for given malloc stack.
        BufferedStackTrace* prevlastuse = nullptr;

        int pos = addrwatch.IsStackPresent(mallocstack);

        if (pos != -1)
           prevlastuse = addrwatch.GetLastUseStack(pos);

        //if (lastusethisrun)
        //{
        //   Printf("Lastuse this run:\n");
        //   lastusethisrun->Print();
        //}

        //if (prevlastuse)
        //{
        //   Printf("Lastuse over all previous runs:\n");
        //   prevlastuse->Print();
        //}

        BufferedStackTrace* mergedlastuse = MergeLastUse(lastusethisrun,prevlastuse);

        if (mergedlastuse)
        {
           Printf("The last read/write to this leaked memory over all runs happened at:\n");

           if (mergedlastuse == prevlastuse)
           {
               uptr diff = lastusethisrun->trace_buffer[lastusethisrun->size-1] - prevlastuse->trace_buffer[prevlastuse->size-1];
               //mergedlastuse->trace_buffer[mergedlastuse->size-1] = lastusethisrun->trace_buffer[lastusethisrun->size];
           }

           (mergedlastuse)->Print();
           WriteWatchAddr(mergedlastuse);
        }
        else
        {
           // malloc stack is last use itself for this run.
           // Instead of storing something let's write 0.
           WriteUptr(0);
        }
        Printf("\n");
    }

}
