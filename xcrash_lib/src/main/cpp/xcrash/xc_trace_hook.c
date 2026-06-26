// Copyright (c) 2019-present, iQIYI, Inc. All rights reserved.
// Licensed under the MIT license (see xc_trace.h for full notice).

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <android/log.h>

#include "xcc_errno.h"
#include "xcc_util.h"
#include "xcc_signal.h"
#include "xcc_meminfo.h"
#include "xc_common.h"
#include "xc_jni.h"
#include "xc_got_hook.h"
#include "xc_trace_hook.h"
#include "xcd_log.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"
#pragma clang diagnostic ignored "-Wpadded"

#define XC_TRACE_HOOK_FAST_CB_NAME    "traceCallbackBeforeDump"
#define XC_TRACE_HOOK_FAST_CB_SIG     "()V"
#define XC_TRACE_HOOK_CB_NAME         "traceCallback"
#define XC_TRACE_HOOK_CB_SIG          "(Ljava/lang/String;Ljava/lang/String;)V"

#define XC_TRACE_HOOK_SIGNAL_CATCHER_NAME   "Signal Catcher"

// max bytes we're willing to copy from a single write() call
#define XC_TRACE_HOOK_MAX_ONE_WRITE (1 << 20)
// total cap per trace
#define XC_TRACE_HOOK_MAX_TOTAL     (8 * (1 << 20))

// ART trace text begins with this marker; skip tombstoned binary handshake before it
#define XTH_TRACE_MARKER     "----- pid "
#define XTH_TRACE_MARKER_LEN 10

// --- init params ---
static int          xth_rethrow;
static unsigned int xth_logcat_system_lines;
static unsigned int xth_logcat_events_lines;
static unsigned int xth_logcat_main_lines;
static int          xth_dump_fds;
static int          xth_dump_network_info;

// --- JNI callbacks ---
static jmethodID xth_fast_cb = NULL;
static jmethodID xth_cb      = NULL;

// --- notifier between signal handler and worker ---
static int xth_notifier = -1;

// --- libraries to hook ---
// We hook multiple libs because ART's SIGQUIT dump path is split across them
// on different Android versions:
//   * Android 7-10 : libart.so -> ::write to stderr/trace file
//   * Android 11+  : libart.so -> libartpalette.so -> tombstoned socket
//                    (connect + writev/write both happen in libartpalette.so)
// We hook both "write" and "connect" in each candidate library, best-effort.
#define XTH_MAX_HOOK_LIBS 6
#define XTH_MAX_HOOK_SYMS 4
typedef struct {
    const char *lib;
    const char *sym;
    void       *orig;   // saved original pointer, NULL if not hooked
    int         installed;
} xth_hook_slot_t;

static xth_hook_slot_t xth_hooks[XTH_MAX_HOOK_LIBS * XTH_MAX_HOOK_SYMS];
static int             xth_hook_count = 0;

// --- signal-catcher tid (locate once) ---
static pid_t xth_signal_catcher_tid = -1;

// --- state shared with the hooked write() ---
// We only mirror writes when xth_active_fd >= 0, and only if the calling tid
// matches xth_signal_catcher_tid. Otherwise we just pass through to the
// original write() without touching anything.
//
// Synchronization protocol (all accesses use __atomic_* builtins):
//   Worker (publish):  store bytes_written=0 RELAXED,
//                      store active_tid RELAXED,
//                      store active_fd  RELEASE   ← publishes all above
//   Hook   (consume):  load  active_fd  ACQUIRE   ← sees tid & bytes_written
//                      load  active_tid RELAXED
//                      fetch_add bytes_written RELAXED
//   Worker (teardown): store active_fd=-1 RELEASE  ← stops new mirrors
//                      (fd stays open until well after unhook, so in-flight
//                       hook calls that cached a local copy of fd are safe)
static int   xth_active_fd     = -1;
static pid_t xth_active_tid    = -1;
static int   xth_bytes_written = 0;
static int   xth_trace_started = 0;

// remember the current trace log path (for callback after finish)
static char xth_current_path[1024] = {0};

typedef ssize_t (*xth_write_t)(int, const void *, size_t);
typedef ssize_t (*xth_write_chk_t)(int, const void *, size_t, size_t);
typedef ssize_t (*xth_writev_t)(int, const struct iovec *, int);

// Pointer to a known-good libc write(). We need this to actually write to our
// own trace fd from inside the hooked write(). If we can't get it, we fall
// back to ::write (which will have been replaced by the linker to our hook in
// the libs we hooked, but libc itself still has the real one).
static xth_write_t      xth_real_write      = NULL;
static xth_write_chk_t  xth_real_write_chk  = NULL;
static xth_writev_t     xth_real_writev     = NULL;

static const void *xth_filter_buf(const void *buf, size_t len, size_t *out_len)
{
    if(__atomic_load_n(&xth_trace_started, __ATOMIC_RELAXED))
    {
        *out_len = len;
        return buf;
    }
    const void *pos = memmem(buf, len, XTH_TRACE_MARKER, XTH_TRACE_MARKER_LEN);
    if(NULL == pos) return NULL;
    __atomic_store_n(&xth_trace_started, 1, __ATOMIC_RELAXED);
    *out_len = len - (size_t)((const char *)pos - (const char *)buf);
    return pos;
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

// Locate the ART "Signal Catcher" thread.
//
// History:
//   * Old xCrash code required SigBlk == 0x1000 (only SIGQUIT blocked).
//   * On modern Android (11+ / 16) the Signal Catcher additionally blocks
//     other signals (e.g. SigBlk = 0x80005204 observed on Android 16/Xiaomi),
//     so we relax the check.
//
// Strategy: scan /proc/self/task and accept the FIRST thread whose name is
// exactly "Signal Catcher". The SigBlk check is best-effort (we still log
// the value for diagnostics) but no longer mandatory.
static void xth_locate_signal_catcher(int log_fd)
{
    char           path[128];
    char           name[64];
    char           line[256];
    DIR           *dir;
    struct dirent *ent;
    FILE          *f;
    pid_t          tid;
    uint64_t       sigblk;

    xth_signal_catcher_tid = -1;

    snprintf(path, sizeof(path), "/proc/%d/task", xc_common_process_id);
    if(NULL == (dir = opendir(path)))
    {
        if(log_fd >= 0)
            xcc_util_write_format(log_fd, "Locate: opendir(%s) failed errno=%d\n", path, errno);
        return;
    }

    int candidate_total = 0;
    while(NULL != (ent = readdir(dir)))
    {
        if(0 != xcc_util_atoi(ent->d_name, &tid)) continue;
        if(tid <= 0) continue;
        candidate_total++;

        xcc_util_get_thread_name(tid, name, sizeof(name));
        if(0 != strcmp(name, XC_TRACE_HOOK_SIGNAL_CATCHER_NAME)) continue;

        sigblk = 0;
        snprintf(path, sizeof(path), "/proc/%d/status", tid);
        if(NULL != (f = fopen(path, "r")))
        {
            while(fgets(line, sizeof(line), f))
            {
                if(1 == sscanf(line, "SigBlk: %"SCNx64, &sigblk)) break;
            }
            fclose(f);
        }

        if(log_fd >= 0)
            xcc_util_write_format(log_fd, "Locate: candidate tid=%d name='%s' SigBlk=0x%"PRIx64"\n",
                                  tid, name, sigblk);

        // accept it (don't insist on the SIGQUIT bit being set, since we
        // already matched by the unique thread name)
        xth_signal_catcher_tid = tid;
        break;
    }
    closedir(dir);

    if(log_fd >= 0)
        xcc_util_write_format(log_fd, "Locate: scanned %d task(s), result tid=%d\n",
                              candidate_total, xth_signal_catcher_tid);
}

static void xth_send_sigquit_to_catcher(void)
{
    if(xth_signal_catcher_tid < 0) xth_locate_signal_catcher(-1);
    if(xth_signal_catcher_tid >= 0)
        syscall(SYS_tgkill, xc_common_process_id, xth_signal_catcher_tid, SIGQUIT);
}

// ---------------------------------------------------------------
// Our hooked write() / writev() / connect()
// ---------------------------------------------------------------

static ssize_t xth_write_hook(int fd, const void *buf, size_t count)
{
    int local_fd = __atomic_load_n(&xth_active_fd, __ATOMIC_ACQUIRE);
    if(local_fd >= 0 && gettid() == __atomic_load_n(&xth_active_tid, __ATOMIC_RELAXED)
       && NULL != buf && count > 0)
    {
        size_t mirror_len;
        const void *mirror_buf = xth_filter_buf(buf, count, &mirror_len);
        if(NULL != mirror_buf)
        {
            size_t to_copy = mirror_len;
            if(to_copy > XC_TRACE_HOOK_MAX_ONE_WRITE) to_copy = XC_TRACE_HOOK_MAX_ONE_WRITE;
            int cur = __atomic_load_n(&xth_bytes_written, __ATOMIC_RELAXED);
            if(cur + (int)to_copy > XC_TRACE_HOOK_MAX_TOTAL)
            {
                int remaining = XC_TRACE_HOOK_MAX_TOTAL - cur;
                to_copy = (remaining > 0) ? (size_t)remaining : 0;
            }
            if(to_copy > 0 && NULL != xth_real_write)
            {
                ssize_t w = xth_real_write(local_fd, mirror_buf, to_copy);
                if(w > 0) __atomic_fetch_add(&xth_bytes_written, (int)w, __ATOMIC_RELAXED);
            }
        }
    }
    if(NULL != xth_real_write) return xth_real_write(fd, buf, count);
    return write(fd, buf, count);
}

// __write_chk(fd, buf, count, dst_len) - fortified wrapper used by
// android::base::WriteFully on Android 14+.
static ssize_t xth_write_chk_hook(int fd, const void *buf, size_t count, size_t dst_len)
{
    int local_fd = __atomic_load_n(&xth_active_fd, __ATOMIC_ACQUIRE);
    if(local_fd >= 0 && gettid() == __atomic_load_n(&xth_active_tid, __ATOMIC_RELAXED)
       && NULL != buf && count > 0)
    {
        size_t mirror_len;
        const void *mirror_buf = xth_filter_buf(buf, count, &mirror_len);
        if(NULL != mirror_buf)
        {
            size_t to_copy = mirror_len;
            if(to_copy > XC_TRACE_HOOK_MAX_ONE_WRITE) to_copy = XC_TRACE_HOOK_MAX_ONE_WRITE;
            int cur = __atomic_load_n(&xth_bytes_written, __ATOMIC_RELAXED);
            if(cur + (int)to_copy > XC_TRACE_HOOK_MAX_TOTAL)
            {
                int remaining = XC_TRACE_HOOK_MAX_TOTAL - cur;
                to_copy = (remaining > 0) ? (size_t)remaining : 0;
            }
            if(to_copy > 0 && NULL != xth_real_write)
            {
                ssize_t w = xth_real_write(local_fd, mirror_buf, to_copy);
                if(w > 0) __atomic_fetch_add(&xth_bytes_written, (int)w, __ATOMIC_RELAXED);
            }
        }
    }
    if(NULL != xth_real_write_chk) return xth_real_write_chk(fd, buf, count, dst_len);
    if(NULL != xth_real_write)     return xth_real_write(fd, buf, count);
    return write(fd, buf, count);
}

// writev(fd, iov, iovcnt) - walk the iovec and mirror each entry.
static ssize_t xth_writev_hook(int fd, const struct iovec *iov, int iovcnt)
{
    int local_fd = __atomic_load_n(&xth_active_fd, __ATOMIC_ACQUIRE);
    if(local_fd >= 0 && gettid() == __atomic_load_n(&xth_active_tid, __ATOMIC_RELAXED)
       && NULL != iov && iovcnt > 0 && NULL != xth_real_write)
    {
        for(int i = 0; i < iovcnt; i++)
        {
            if(NULL == iov[i].iov_base || 0 == iov[i].iov_len) continue;
            size_t mirror_len;
            const void *mirror_buf = xth_filter_buf(iov[i].iov_base, iov[i].iov_len, &mirror_len);
            if(NULL == mirror_buf) continue;
            size_t to_copy = mirror_len;
            if(to_copy > XC_TRACE_HOOK_MAX_ONE_WRITE) to_copy = XC_TRACE_HOOK_MAX_ONE_WRITE;
            int cur = __atomic_load_n(&xth_bytes_written, __ATOMIC_RELAXED);
            if(cur + (int)to_copy > XC_TRACE_HOOK_MAX_TOTAL)
            {
                int remaining = XC_TRACE_HOOK_MAX_TOTAL - cur;
                to_copy = (remaining > 0) ? (size_t)remaining : 0;
            }
            if(to_copy == 0) break;
            ssize_t w = xth_real_write(local_fd, mirror_buf, to_copy);
            if(w > 0) __atomic_fetch_add(&xth_bytes_written, (int)w, __ATOMIC_RELAXED);
        }
    }
    if(NULL != xth_real_writev) return xth_real_writev(fd, iov, iovcnt);
    return writev(fd, iov, iovcnt);
}

// connect() hook is intentionally omitted: write() interception is sufficient
// and keeps us from interfering with ART's tombstoned socket handshake.

// ---------------------------------------------------------------
// Trace file helpers (duplicated tiny bits from xc_trace.c to avoid
// exposing new symbols there)
// ---------------------------------------------------------------

static int xth_logs_filter(const struct dirent *entry)
{
    size_t len;
    if(DT_REG != entry->d_type) return 0;
    len = strlen(entry->d_name);
    if(len < XC_COMMON_LOG_NAME_MIN_TRACE) return 0;
    if(0 != memcmp(entry->d_name, XC_COMMON_LOG_PREFIX"_", XC_COMMON_LOG_PREFIX_LEN + 1)) return 0;
    if(0 != memcmp(entry->d_name + (len - XC_COMMON_LOG_SUFFIX_TRACE_LEN),
                   XC_COMMON_LOG_SUFFIX_TRACE, XC_COMMON_LOG_SUFFIX_TRACE_LEN)) return 0;
    return 1;
}

static int xth_logs_clean(void)
{
    struct dirent **entry_list;
    char            pathname[1024];
    int             n, i, r = 0;
    if(0 > (n = scandir(xc_common_log_dir, &entry_list, xth_logs_filter, alphasort))) return XCC_ERRNO_SYS;
    for(i = 0; i < n; i++)
    {
        snprintf(pathname, sizeof(pathname), "%s/%s", xc_common_log_dir, entry_list[i]->d_name);
        if(0 != unlink(pathname)) r = XCC_ERRNO_SYS;
    }
    free(entry_list);
    return r;
}

static int xth_write_header(int fd, uint64_t trace_time)
{
    int  r;
    char buf[1024];
    xcc_util_get_dump_header(buf, sizeof(buf),
                             XCC_UTIL_CRASH_TYPE_ANR,
                             xc_common_time_zone,
                             xc_common_start_time,
                             trace_time,
                             xc_common_app_id,
                             xc_common_app_version,
                             xc_common_api_level,
                             xc_common_os_version,
                             xc_common_kernel_version,
                             xc_common_abi_list,
                             xc_common_manufacturer,
                             xc_common_brand,
                             xc_common_model,
                             xc_common_build_fingerprint);
    if(0 != (r = xcc_util_write_str(fd, buf))) return r;
    return xcc_util_write_format(fd, "pid: %d  >>> %s <<<\n\n", xc_common_process_id, xc_common_process_name);
}

// libc write-family symbols we want to intercept. _FORTIFY_SOURCE=2 in newer
// NDK / platform builds redirects write(buf, n) to __write_chk(buf, n, sz),
// which is the one libbase.so::WriteFully actually calls on Android 14+.
// We also catch writev for completeness.
static const char *const xth_hook_syms[] = {
    "write",
    "__write_chk",
    "writev",
    NULL,
};

static const char *const xth_hook_lib_basenames[] = {
    "libbase.so",
    "libartpalette-system.so",
    "libartpalette.so",
    "libtombstoned_client.so",  // Android 10 some builds route here
    "libart.so",
    NULL,
};

static void *xth_pick_hook_for_sym(const char *sym)
{
    if(0 == strcmp(sym, "write"))       return (void *)xth_write_hook;
    if(0 == strcmp(sym, "__write_chk")) return (void *)xth_write_chk_hook;
    if(0 == strcmp(sym, "writev"))      return (void *)xth_writev_hook;
    return NULL;
}

static int xth_install_all_hooks(int log_fd)
{
    int total_installed = 0;
    xth_hook_count = 0;

    for(int li = 0; NULL != xth_hook_lib_basenames[li]; li++)
    {
        const char *lib = xth_hook_lib_basenames[li];

        for(int si = 0; NULL != xth_hook_syms[si]; si++)
        {
            const char *sym = xth_hook_syms[si];
            void *hook_fn = xth_pick_hook_for_sym(sym);
            if(NULL == hook_fn) continue;

            if(xth_hook_count >= (int)(sizeof(xth_hooks) / sizeof(xth_hooks[0]))) break;

            xth_hook_slot_t *s = &xth_hooks[xth_hook_count];
            s->lib = lib;
            s->sym = sym;
            s->orig = NULL;
            s->installed = 0;

            int r = xc_got_hook(lib, sym, hook_fn, &s->orig);
            if(0 == r)
            {
                s->installed = 1;
                total_installed++;
                if(log_fd >= 0)
                    xcc_util_write_format(log_fd, "Hooked %s() in %s\n", sym, lib);
            }
            xth_hook_count++;
        }
    }
    return total_installed;
}

static void xth_uninstall_all_hooks(void)
{
    for(int i = 0; i < xth_hook_count; i++)
    {
        xth_hook_slot_t *s = &xth_hooks[i];
        if(s->installed && NULL != s->orig)
        {
            xc_got_unhook(s->lib, s->sym, s->orig);
        }
        s->installed = 0;
        s->orig = NULL;
    }
    xth_hook_count = 0;
}

// ---------------------------------------------------------------
// Worker thread: does the actual dump when notified
// ---------------------------------------------------------------

static void *xth_worker(void *arg)
{
    JNIEnv         *env = NULL;
    uint64_t        data;
    struct timeval  tv;
    // Timestamp of the last trace we actually produced, monotonic-ish (uses
    // gettimeofday which is fine for this purpose). Used to debounce the
    // "second SIGQUIT" that Android frameworks commonly send ~2-3s after the
    // first one (e.g. AMS's ProcessErrorStateRecord does a 2nd pass trace
    // dump). Without this we would produce two .anr.xcrash files per ANR.
    uint64_t        last_dump_us = 0;
    static const uint64_t XTH_DEBOUNCE_WINDOW_US = 10ULL * 1000 * 1000; // 10s
    (void)arg;

    pthread_detach(pthread_self());

    JavaVMAttachArgs attach_args = {
        .version = XC_JNI_VERSION,
        .name    = "xcrash_trace_hk",
        .group   = NULL
    };
    if(JNI_OK != (*xc_common_vm)->AttachCurrentThread(xc_common_vm, &env, &attach_args)) return NULL;

    while(1)
    {
        XCC_UTIL_TEMP_FAILURE_RETRY(read(xth_notifier, &data, sizeof(data)));

        if(xc_common_native_crashed || xc_common_java_crashed) break;

        // fast callback (pre-dump)
        if(NULL != xth_fast_cb)
        {
            (*env)->CallStaticVoidMethod(env, xc_common_cb_class, xth_fast_cb);
            XC_JNI_IGNORE_PENDING_EXCEPTION();
        }

        if(0 != gettimeofday(&tv, NULL)) continue;
        uint64_t trace_time = (uint64_t)(tv.tv_sec) * 1000 * 1000 + (uint64_t)tv.tv_usec;

        // Debounce: AMS / Watchdog typically sends a 2nd SIGQUIT a few seconds
        // after the first one to grab a "second pass" trace. We don't want
        // that to produce a second tombstone. Drop SIGQUITs that arrive within
        // 10s of the previous one we successfully captured.
        if(last_dump_us > 0 && trace_time > last_dump_us
           && (trace_time - last_dump_us) < XTH_DEBOUNCE_WINDOW_US)
        {
            __android_log_print(ANDROID_LOG_INFO, "xcrash",
                                "trace_hook: debounced SIGQUIT (%" PRIu64 "us since last)",
                                trace_time - last_dump_us);
            continue;
        }

        // keep only the latest trace
        if(0 != xth_logs_clean()) continue;

        int fd = xc_common_open_trace_log(xth_current_path, sizeof(xth_current_path), trace_time);
        if(fd < 0) continue;

        if(0 != xth_write_header(fd, trace_time)) { xc_common_close_trace_log(fd); continue; }
        if(0 != xcc_util_write_format(fd, XCC_UTIL_THREAD_SEP"Cmd line: %s\n", xc_common_process_name))
        { xc_common_close_trace_log(fd); continue; }
        if(0 != xcc_util_write_str(fd, "Mode: xCrash HookWrite\n"))
        { xc_common_close_trace_log(fd); continue; }

        // ensure signal catcher tid is known (with diagnostic logging into trace)
        if(xth_signal_catcher_tid < 0) xth_locate_signal_catcher(fd);
        xcc_util_write_format(fd, "Signal Catcher tid: %d\n", xth_signal_catcher_tid);

        // install GOT hooks on all candidate libs (libbase.so, libartpalette*.so, libart.so)
        int hooked = xth_install_all_hooks(fd);
        xcc_util_write_format(fd, "Hook install: %d write() slot(s) patched.\n", hooked);

        if(hooked <= 0 || xth_signal_catcher_tid < 0)
        {
            xcc_util_write_str(fd, "Hook failed or Signal Catcher not found.\n");
            xth_uninstall_all_hooks();
        }
        else
        {
            // prime mirror-state and trigger ART's signal catcher.
            // Order matters: bytes_written and tid must be visible before
            // active_fd is published (RELEASE), because hook functions
            // ACQUIRE-load active_fd as the gate.
            __atomic_store_n(&xth_bytes_written, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&xth_trace_started, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&xth_active_tid, xth_signal_catcher_tid, __ATOMIC_RELAXED);
            __atomic_store_n(&xth_active_fd, fd, __ATOMIC_RELEASE);

            xth_send_sigquit_to_catcher();

            // wait for ART to finish dumping. Heuristic: idle for 500ms after
            // last activity, capped at 5s. If we never saw output, also break.
            int idle_ms    = 0;
            int last_seen  = 0;
            for(int waited = 0; waited < 5000; waited += 50)
            {
                usleep(50 * 1000);
                int cur = __atomic_load_n(&xth_bytes_written, __ATOMIC_ACQUIRE);
                if(cur != last_seen)
                {
                    last_seen = cur;
                    idle_ms = 0;
                }
                else if(cur > 0)
                {
                    idle_ms += 50;
                    if(idle_ms >= 500) break;
                }
            }

            // Tear down: close the gate first so new hook invocations skip the
            // mirror path, then restore GOT slots. The fd is NOT closed here —
            // it stays open for the extra sections below, which provides a
            // natural grace period for any in-flight hook call that already
            // snapshot local_fd before we flipped the gate.
            __atomic_store_n(&xth_active_fd, -1, __ATOMIC_RELEASE);
            __atomic_store_n(&xth_active_tid, -1, __ATOMIC_RELAXED);

            xth_uninstall_all_hooks();

            if(last_seen == 0)
                xcc_util_write_str(fd, "ART did not produce any trace output via write().\n");
        }

        xcc_util_write_str(fd, "\n"XCC_UTIL_THREAD_END"\n");

        // extras
        xcc_util_record_logcat(fd, xc_common_process_id, xc_common_api_level,
                               xth_logcat_system_lines, xth_logcat_events_lines, xth_logcat_main_lines);
        if(xth_dump_fds)           xcc_util_record_fds(fd, xc_common_process_id);
        if(xth_dump_network_info)  xcc_util_record_network_info(fd, xc_common_process_id, xc_common_api_level);
        xcc_meminfo_record(fd, xc_common_process_id);

        xc_common_close_trace_log(fd);

        // mark the moment we just produced a trace so the next SIGQUIT within
        // XTH_DEBOUNCE_WINDOW_US is dropped
        last_dump_us = trace_time;

        // re-throw SIGQUIT is a no-op here; ART already got it.
        (void)xth_rethrow;

        // slow callback
        if(NULL != xth_cb)
        {
            jstring j_path = (*env)->NewStringUTF(env, xth_current_path);
            if(NULL != j_path)
            {
                (*env)->CallStaticVoidMethod(env, xc_common_cb_class, xth_cb, j_path, NULL);
                XC_JNI_IGNORE_PENDING_EXCEPTION();
                (*env)->DeleteLocalRef(env, j_path);
            }
        }
    }

    (*xc_common_vm)->DetachCurrentThread(xc_common_vm);
    return NULL;
}

// ---------------------------------------------------------------
// Signal handler (just notify the worker)
// ---------------------------------------------------------------

static void xth_sig_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si; (void)uc;
    if(xth_notifier >= 0)
    {
        uint64_t one = 1;
        XCC_UTIL_TEMP_FAILURE_RETRY(write(xth_notifier, &one, sizeof(one)));
    }
}

// On-demand trigger (for Java-side WatchDog / nativeAnrHandler path).
void xc_trace_hook_handler2(void)
{
    if(xth_notifier >= 0)
    {
        uint64_t data = 1;
        XCC_UTIL_TEMP_FAILURE_RETRY(write(xth_notifier, &data, sizeof(data)));
    }
}

// ---------------------------------------------------------------
// Public init
// ---------------------------------------------------------------

static void xth_init_callback(JNIEnv *env)
{
    if(NULL == xc_common_cb_class) return;
    xth_fast_cb = (*env)->GetStaticMethodID(env, xc_common_cb_class,
                                            XC_TRACE_HOOK_FAST_CB_NAME, XC_TRACE_HOOK_FAST_CB_SIG);
    XC_JNI_CHECK_NULL_AND_PENDING_EXCEPTION(xth_fast_cb, err);
    xth_cb = (*env)->GetStaticMethodID(env, xc_common_cb_class,
                                       XC_TRACE_HOOK_CB_NAME, XC_TRACE_HOOK_CB_SIG);
    XC_JNI_CHECK_NULL_AND_PENDING_EXCEPTION(xth_cb, err);
    return;
 err:
    xth_fast_cb = NULL;
    xth_cb = NULL;
}

int xc_trace_hook_init(JNIEnv *env,
                       int rethrow,
                       unsigned int logcat_system_lines,
                       unsigned int logcat_events_lines,
                       unsigned int logcat_main_lines,
                       int dump_fds,
                       int dump_network_info)
{
    int r;
    pthread_t thd;

    // hook mode only runs on ART (API >= 21); it also really targets 11+
    if(xc_common_api_level < 21) return 0;

    xth_rethrow = rethrow;
    xth_logcat_system_lines = logcat_system_lines;
    xth_logcat_events_lines = logcat_events_lines;
    xth_logcat_main_lines   = logcat_main_lines;
    xth_dump_fds            = dump_fds;
    xth_dump_network_info   = dump_network_info;

    // Cache a pointer to the *real* libc write() so our hook can still
    // actually write to the trace fd even after libart's write slot is
    // replaced by our stub. Fallback to ::write at call site if NULL.
    xth_real_write     = (xth_write_t)dlsym(RTLD_DEFAULT, "write");
    xth_real_write_chk = (xth_write_chk_t)dlsym(RTLD_DEFAULT, "__write_chk");
    xth_real_writev    = (xth_writev_t)dlsym(RTLD_DEFAULT, "writev");

    xth_init_callback(env);

    if(0 > (xth_notifier = eventfd(0, EFD_CLOEXEC))) return XCC_ERRNO_SYS;

    if(0 != (r = xcc_signal_trace_register(xth_sig_handler))) goto err2;

    if(0 != (r = pthread_create(&thd, NULL, xth_worker, NULL))) goto err1;

    return 0;

 err1:
    xcc_signal_trace_unregister();
 err2:
    close(xth_notifier);
    xth_notifier = -1;
    return r;
}

#pragma clang diagnostic pop
