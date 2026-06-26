// Copyright (c) 2019-present, iQIYI, Inc. All rights reserved.
//
// Licensed under the MIT license (see xc_got_hook.h for full notice).

// Minimal, read-the-runtime-linker style PLT/GOT hook.
// - Uses dl_iterate_phdr to find the in-memory mapping of the target library.
// - Walks the PT_DYNAMIC segment to locate .dynsym / .dynstr / .rel(a).plt / .rel(a).dyn.
// - Finds the GOT slot whose relocation references the requested symbol name
//   and overwrites it in-place.
//
// Supports:
//   - aarch64 / x86_64           : RELA,  R_*_JUMP_SLOT / R_*_GLOB_DAT
//   - arm    / i686              : REL,   R_*_JUMP_SLOT / R_*_GLOB_DAT
//
// Only one symbol is hooked per call; this is sufficient for our use case.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h>
#include <android/log.h>
#include "xc_got_hook.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-statement-expression"
#pragma clang diagnostic ignored "-Wcast-qual"
#pragma clang diagnostic ignored "-Wcast-align"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wunused-macros"

#if defined(__LP64__)
#define XC_GOT_ELFW_R_SYM(i)   ELF64_R_SYM(i)
#define XC_GOT_ELFW_R_TYPE(i)  ELF64_R_TYPE(i)
#else
#define XC_GOT_ELFW_R_SYM(i)   ELF32_R_SYM(i)
#define XC_GOT_ELFW_R_TYPE(i)  ELF32_R_TYPE(i)
#endif

#if defined(__aarch64__)
#define XC_GOT_R_JUMP_SLOT  R_AARCH64_JUMP_SLOT
#define XC_GOT_R_GLOB_DAT   R_AARCH64_GLOB_DAT
#define XC_GOT_USE_RELA     1
#elif defined(__x86_64__)
#define XC_GOT_R_JUMP_SLOT  R_X86_64_JUMP_SLOT
#define XC_GOT_R_GLOB_DAT   R_X86_64_GLOB_DAT
#define XC_GOT_USE_RELA     1
#elif defined(__arm__)
#define XC_GOT_R_JUMP_SLOT  R_ARM_JUMP_SLOT
#define XC_GOT_R_GLOB_DAT   R_ARM_GLOB_DAT
#define XC_GOT_USE_RELA     0
#elif defined(__i386__)
#define XC_GOT_R_JUMP_SLOT  R_386_JMP_SLOT
#define XC_GOT_R_GLOB_DAT   R_386_GLOB_DAT
#define XC_GOT_USE_RELA     0
#else
#define XC_GOT_R_JUMP_SLOT  0
#define XC_GOT_R_GLOB_DAT   0
#define XC_GOT_USE_RELA     0
#endif

typedef struct {
    const char  *pathname;
    const char  *symbol;
    void        *new_func;
    void       **old_func;
    int          done;
    int          hit_count;   // total instances hooked across all loaded libs
    int          stop_at_first; // 1 = legacy behaviour (stop after 1 hit)
} xc_got_ctx_t;

static int xc_got_path_match(const char *full, const char *needle)
{
    if(NULL == full || NULL == needle) return 0;
    if(0 == strcmp(full, needle)) return 1;

    // also match by basename (the last path component), in case the caller
    // passed a different apex path than what shows up in dl_iterate_phdr.
    const char *a = strrchr(full,   '/');
    const char *b = strrchr(needle, '/');
    a = (NULL == a) ? full   : a + 1;
    b = (NULL == b) ? needle : b + 1;
    return 0 == strcmp(a, b);
}

static int xc_got_write_slot(ElfW(Addr) *slot, void *new_val, void **out_old)
{
    long page_size = sysconf(_SC_PAGESIZE);
    if(page_size <= 0) page_size = 4096;

    uintptr_t page = (uintptr_t)slot & ~((uintptr_t)page_size - 1);
    if(0 != mprotect((void *)page, (size_t)page_size, PROT_READ | PROT_WRITE)) return -1;

    // Atomically swap the GOT slot so concurrent PLT calls in other threads
    // never observe a torn pointer value.
    ElfW(Addr) old_val = __atomic_exchange_n(slot, (ElfW(Addr))new_val, __ATOMIC_ACQ_REL);
    if(NULL != out_old) *out_old = (void *)old_val;

    __builtin___clear_cache((char *)slot, (char *)slot + sizeof(ElfW(Addr)));
    return 0;
}

static int xc_got_process_one(struct dl_phdr_info *info, xc_got_ctx_t *ctx)
{
    ElfW(Dyn)  *dyn        = NULL;
    const char *dynstr     = NULL;
    ElfW(Sym)  *dynsym     = NULL;
    void       *rel_plt    = NULL; size_t rel_plt_sz = 0; int rel_plt_rela = 0;
    void       *rel_dyn    = NULL; size_t rel_dyn_sz = 0; int rel_dyn_rela = 0;
    size_t      rel_ent    = 0;
    size_t      rela_ent   = 0;
    size_t      i;

    // locate PT_DYNAMIC
    for(i = 0; i < info->dlpi_phnum; i++)
    {
        if(PT_DYNAMIC == info->dlpi_phdr[i].p_type)
        {
            dyn = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if(NULL == dyn) return 0;

    // walk DT_* entries
    for(; DT_NULL != dyn->d_tag; dyn++)
    {
        switch(dyn->d_tag)
        {
            case DT_STRTAB:  dynstr = (const char *)(info->dlpi_addr + dyn->d_un.d_ptr); break;
            case DT_SYMTAB:  dynsym = (ElfW(Sym) *)(info->dlpi_addr + dyn->d_un.d_ptr);  break;
            case DT_JMPREL:  rel_plt = (void *)(info->dlpi_addr + dyn->d_un.d_ptr);      break;
            case DT_PLTRELSZ:rel_plt_sz = (size_t)dyn->d_un.d_val;                        break;
            case DT_PLTREL:  rel_plt_rela = (DT_RELA == (ElfW(Sxword))dyn->d_un.d_val);   break;
            case DT_REL:     rel_dyn = (void *)(info->dlpi_addr + dyn->d_un.d_ptr); rel_dyn_rela = 0; break;
            case DT_RELSZ:   rel_dyn_sz = (size_t)dyn->d_un.d_val;                        break;
            case DT_RELA:    rel_dyn = (void *)(info->dlpi_addr + dyn->d_un.d_ptr); rel_dyn_rela = 1; break;
            case DT_RELASZ:  rel_dyn_sz = (size_t)dyn->d_un.d_val;                        break;
            case DT_RELENT:  rel_ent  = (size_t)dyn->d_un.d_val;                          break;
            case DT_RELAENT: rela_ent = (size_t)dyn->d_un.d_val;                          break;
            default: break;
        }
    }
    if(NULL == dynstr || NULL == dynsym) return 0;
    if(0 == rel_ent)  rel_ent  = sizeof(ElfW(Rel));
    if(0 == rela_ent) rela_ent = sizeof(ElfW(Rela));

    // search in rel.plt and rel.dyn
    for(int pass = 0; pass < 2 && !ctx->done; pass++)
    {
        void   *tbl  = (0 == pass) ? rel_plt    : rel_dyn;
        size_t  sz   = (0 == pass) ? rel_plt_sz : rel_dyn_sz;
        int     rela = (0 == pass) ? rel_plt_rela : rel_dyn_rela;
        size_t  step = rela ? rela_ent : rel_ent;
        if(NULL == tbl || 0 == sz || 0 == step) continue;

        for(size_t off = 0; off + step <= sz; off += step)
        {
            ElfW(Addr)  r_offset;
            ElfW(Xword) r_info;
            if(rela)
            {
                ElfW(Rela) *ra = (ElfW(Rela) *)((uint8_t *)tbl + off);
                r_offset = ra->r_offset;
                r_info   = ra->r_info;
            }
            else
            {
                ElfW(Rel) *re = (ElfW(Rel) *)((uint8_t *)tbl + off);
                r_offset = re->r_offset;
                r_info   = re->r_info;
            }

            unsigned long t = (unsigned long)XC_GOT_ELFW_R_TYPE(r_info);
            if(t != (unsigned long)XC_GOT_R_JUMP_SLOT && t != (unsigned long)XC_GOT_R_GLOB_DAT) continue;

            ElfW(Sym)  *sym   = &dynsym[XC_GOT_ELFW_R_SYM(r_info)];
            const char *sname = dynstr + sym->st_name;
            if(0 != strcmp(sname, ctx->symbol)) continue;

            ElfW(Addr) *slot = (ElfW(Addr) *)(info->dlpi_addr + r_offset);
            if(0 == xc_got_write_slot(slot, ctx->new_func, ctx->old_func))
            {
                ctx->hit_count++;
                if(ctx->stop_at_first)
                {
                    ctx->done = 1;
                    return 1;
                }
                // continue scanning the rest of the relocations in this lib,
                // because a single imported symbol can have both a .plt and a
                // .dyn slot.
            }
        }
    }
    return 0;
}

static int xc_got_iter_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    xc_got_ctx_t *ctx = (xc_got_ctx_t *)data;
    if(ctx->done) return 0;
    if(NULL == info->dlpi_name || '\0' == info->dlpi_name[0]) return 0;
    if(!xc_got_path_match(info->dlpi_name, ctx->pathname)) return 0;
    xc_got_process_one(info, ctx);
    return ctx->done ? 1 : 0;
}

int xc_got_hook(const char *lib_pathname,
                const char *symbol,
                void *new_func,
                void **old_func)
{
    if(NULL == lib_pathname || NULL == symbol || NULL == new_func) return -1;
    if(0 == XC_GOT_R_JUMP_SLOT) return -1; // unsupported arch

    xc_got_ctx_t ctx;
    ctx.pathname = lib_pathname;
    ctx.symbol   = symbol;
    ctx.new_func = new_func;
    ctx.old_func = old_func;
    ctx.done     = 0;
    ctx.hit_count = 0;
    ctx.stop_at_first = 0; // hook every matching loaded instance
    dl_iterate_phdr(xc_got_iter_cb, &ctx);
    return (ctx.hit_count > 0) ? 0 : -1;
}

int xc_got_unhook(const char *lib_pathname,
                  const char *symbol,
                  void *old_func)
{
    if(NULL == old_func) return 0;
    return xc_got_hook(lib_pathname, symbol, old_func, NULL);
}

#pragma clang diagnostic pop
