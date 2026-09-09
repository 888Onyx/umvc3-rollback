// audio_preserve.cpp — see audio_preserve.h. Walk-driven per-object keep-live for the streaming audio engine.
// "Let a slab just be a way to capture data" — we preserve the OBJECT inside the slab (by extent), the slab/page
// reverts normally. save() walks from sSound (audio_probe::collect) for the live leaf objects, adds the sSound +
// ss_sub containers, snapshots each into a private scratch (not in the arena). restore() writes them back over the
// reverted slabs. Raw reads/writes only (freeze-safe), bounded by VirtualQuery readability.
#include "audio_preserve.h"
#include "audio_probe.h"
#include "arena.h"
#include "addr.h"
#include "log.h"
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace audio_preserve {

namespace {

static constexpr size_t SNAP_CAP = 2 * 1024 * 1024;   // audio set is ~150KB; 2MB headroom
static uint8_t  g_snap[SNAP_CAP];
struct Reg { uintptr_t base; uint32_t size; size_t off; };
static const int MAX_REG = 256;
static Reg g_reg[MAX_REG];
static int g_reg_n = 0;
static size_t g_used = 0;
static int64_t c_runs = 0, c_dropped = 0;

static bool readable(uintptr_t p, size_t n){
    if(!p || n==0) return false;
    if(arena::is_arena_addr(p) && arena::is_arena_addr(p+n-1))
        return arena::is_committed_addr(p) && arena::is_committed_addr(p+n-1);
    MEMORY_BASIC_INFORMATION mbi;
    if(!VirtualQuery((void*)p,&mbi,sizeof(mbi))) return false;
    if(mbi.State!=MEM_COMMIT) return false;
    if(mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD)) return false;
    uintptr_t end=(uintptr_t)mbi.BaseAddress+mbi.RegionSize;
    return p+n<=end;
}

// snapshot one region (live -> scratch), record it. Dedup by base (last write wins).
static void grab(uintptr_t base, uint32_t size){
    if(!base || !size || !arena::is_arena_addr(base)) return;
    if(!readable(base, size)) return;
    for(int i=0;i<g_reg_n;i++) if(g_reg[i].base==base){ // already grabbed (e.g. resource reached twice)
        return; }
    if(g_reg_n>=MAX_REG || g_used+size>SNAP_CAP){ c_dropped++; return; }
    memcpy(g_snap+g_used, (void*)base, size);
    g_reg[g_reg_n].base=base; g_reg[g_reg_n].size=size; g_reg[g_reg_n].off=g_used;
    g_used += size; g_reg_n++;
}

} // anon

void save(){
    g_reg_n = 0; g_used = 0; c_runs++;

    // (1) the two CONTAINERS (known extents) — keep slot pointers / mixer state coherent with the kept-live leaves.
    uintptr_t pss = addr::resolve(0x140E18520);
    if(readable(pss,8)){
        uintptr_t ss = *(uintptr_t*)pss;
        if(ss && arena::is_arena_addr(ss)){
            grab(ss, 0x1E100);                                    // sSound body (DTI-confirmed size)
            if(readable(ss+0x40,8)){ uintptr_t sub=*(uintptr_t*)(ss+0x40);
                if(sub && arena::is_arena_addr(sub)) grab(sub, 0x5000); }   // NativeSystemXAudio2 sub-object
        }
    }
    // (2) the WALK-discovered streaming leaves (voiceP/channel/strips/resource) — the non-reflected engine objects.
    audio_probe::Region regs[256];
    int nr = audio_probe::collect(regs, 256);
    for(int i=0;i<nr;i++) grab(regs[i].base, regs[i].size);

    static int s_log = 0;
    if(s_log < 3){ s_log++;
        bool w=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("AUDIO-PRESERVE/save: %d objects, %zu bytes captured (per-object keep-live; pages revert normally) dropped=%lld",
                     g_reg_n, g_used, (long long)c_dropped);
        rblog::suppress(w);
    }
}

void restore(){
    int wrote=0;
    for(int i=0;i<g_reg_n;i++){
        if(readable(g_reg[i].base, g_reg[i].size)){
            memcpy((void*)g_reg[i].base, g_snap+g_reg[i].off, g_reg[i].size); wrote++;
        }
    }
    static int s_log = 0;
    if(s_log < 3){ s_log++;
        bool w=rblog::is_suppressed(); rblog::suppress(false);
        rblog::write("AUDIO-PRESERVE/restore: wrote back %d/%d audio objects (live epoch restored over reverted slabs)",
                     wrote, g_reg_n);
        rblog::suppress(w);
    }
}

} // namespace audio_preserve
