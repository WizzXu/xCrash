// Copyright (c) 2019-present, iQIYI, Inc. All rights reserved.
// Licensed under the MIT license (see xc_trace.h for full notice).
//
// "Matrix-style" ANR trace capture mode for xCrash.
//
// Idea (compatible with Android 11 / 12 / 13 / 14 / 15 / 16):
//   * We install our own SIGQUIT handler.
//   * On SIGQUIT, we GOT-hook libart.so's imported "write" so that any data
//     coming from the in-process ART "Signal Catcher" thread (which performs
//     Runtime::DumpForSigQuit and then writes to tombstoned via PaletteWrite-
//     CrashThreadStacks -> libc::write) is mirrored into our own trace file.
//   * We then re-raise SIGQUIT to the Signal Catcher thread so the ART side
//     dump runs as usual, transparently for the system.
//   * After the dump finishes, we restore the original GOT slot.
//
// We do NOT call Runtime::DumpForSigQuit ourselves in this mode, which avoids
// the ABI-instability problems that mode has on Android 13+ / OEM ROMs.

#ifndef XC_TRACE_HOOK_H
#define XC_TRACE_HOOK_H 1

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

int xc_trace_hook_init(JNIEnv *env,
                       int rethrow,
                       unsigned int logcat_system_lines,
                       unsigned int logcat_events_lines,
                       unsigned int logcat_main_lines,
                       int dump_fds,
                       int dump_network_info);

void xc_trace_hook_handler2(void);

#ifdef __cplusplus
}
#endif

#endif
