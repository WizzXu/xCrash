// Copyright (c) 2019-present, iQIYI, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Simple single-symbol PLT/GOT hook for a loaded shared library.
// Works by parsing the file-backed ELF (via xc_dl) to locate .rel(a).plt /
// .rel(a).dyn entries that reference the target imported symbol name, then
// overwriting the matching slot in the live process memory image of the library.
//
// This is intentionally minimal and used only by the xCrash ANR "hook mode".
// NOT a general-purpose replacement for xhook / bhook.

#ifndef XC_GOT_HOOK_H
#define XC_GOT_HOOK_H 1

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hook a single imported symbol in a loaded shared library.
// - lib_pathname : absolute path that appears in /proc/self/maps (e.g. libart.so path).
// - symbol       : imported symbol name (e.g. "write").
// - new_func     : replacement function pointer.
// - old_func     : (out, optional) receives the original function pointer on success.
//
// Returns 0 on success, non-zero on failure.
int xc_got_hook(const char *lib_pathname,
                const char *symbol,
                void *new_func,
                void **old_func);

// Restore a previously hooked symbol.
int xc_got_unhook(const char *lib_pathname,
                  const char *symbol,
                  void *old_func);

#ifdef __cplusplus
}
#endif

#endif
