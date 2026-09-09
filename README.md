# umvc3 rollback

Rollback netcode for Ultimate Marvel vs. Capcom 3 (MT Framework, x86-64), built as an
injected `dinput8.dll`. No source, no symbols, no debug build — everything here was derived
from the retail binary in Ghidra and confirmed against a running game.

63 translation units, ~26k lines. It builds, it runs, it rolls back. It does not yet hold a
match together. The honest scope is at the bottom.

---

## The approach, and what it costs

An emulator gets rollback for free: it owns the machine, so a savestate is the whole machine.
A native game gives you none of that. The usual answer is to reimplement the tick so you know
what every piece of state is. This project took the other road:

**Own the memory instead of the tick.**

A 2GB arena is reserved before the game's first instruction, and `VirtualAlloc` / `VirtualFree`
/ `HeapAlloc` / `HeapFree` / `HeapReAlloc` are IAT-hooked so every allocation the engine makes
lands inside it. `GetWriteWatch` then reports exactly which pages were dirtied per frame. Save
is those pages; restore is writing them back.

That buys four things without understanding a single struct:

| | |
|---|---|
| **P1 — own the backing** | every byte of engine state is inside a range we can snapshot |
| **P2 — object map** | `addr → {size, birth_frame, death_frame\|ALIVE, generation}`, free, because every alloc and free is intercepted |
| **P3 — own the reuse** | a freed slab is not returned to any free list until its death frame is past the rollback horizon, so a rolled-back pointer cannot land on a stranger |
| **P4 — object-granular revert** | restore a chosen object rather than the whole page |

The cost is that a page revert is *too* faithful. It reinstates bytes that were correct at
save time and are wrong now — a handle to a resource the driver has since released, a node
still threaded into a list that has been rebuilt, a pointer to something that has died.
That produced the bulk of this project's crashes, and most of the code here is the answer to them.

### The exceptions to the revert

`arena::load`'s page revert is the default discipline, not the whole story. Three mechanisms
narrow it:

- **windowed restore** (`arena.cpp`, on by default) — revert the dirty window, not the arena
- **`F_REDERIVE` page exclusions** — pages holding derived/render output are skipped entirely,
  because the engine rebuilds them anyway and reverting them fights it
- **`set_coherent_full_ranges`** — a *scoped* full revert for the allocator's own list pool,
  where partial reversion breaks the list

`dynamic_restore.h` is the registry that formalizes this: a sparse override table, consulted
only where the blind revert is known to be wrong. Exact revert means no descriptor. The
shipped registry is a skeleton that carries the three hand-written preserve/null-stale fixes;
`arena::load` and `restore_allocators` are untouched by it.

### Identity

Restoring a pointer *by identity* rather than by byte requires knowing that the object at an
address is the same object the edge captured. It usually isn't enough to check the vtable: the
allocator hands the same slab back out to a new object of the same type, so address and type
both match and an edge binds to an impostor. `idspine.cpp` stamps every allocator block with a
monotonic birth serial, keyed on **block base** so it is alignment-independent, giving identity
the missing third coordinate. It writes nothing into game memory; `byid` reads it to classify
stale references (same address, same vtable, different birth serial = a reused slab), but nothing
restores *by* stamp unless the F2 authoritative splice is armed.

### Severing

`edge_break.h` is the piece worth reading if you read one thing. Every probe that answers
"which edges does the revert break?" by *looking at objects* is limited to the objects it can
see — the ones with a known vtable, at a block's payload start, inside the tracked regions,
that lived long enough to be sampled. Anything pooled, POD, slab-packed, or short-lived is
structurally invisible to it, so a repair table built from that data only ever fixes the shadow
the probe casts.

The invariant sidesteps it. Out-of-arena memory is never reverted, so any qword that the revert
*changed* and that held a pointer to out-of-arena memory on either side of the change is a
cross-boundary edge the revert just broke. Both halves of that test are already sitting at the
revert site — `arena::load` has the pre-revert page and then writes the post-revert page over
it. Diffing them is complete by construction: every reverted byte is examined, regardless of
type, layout, pooling, allocator, or lifetime. No type map required.

---

## Input

The input seam is **XInput, not DirectInput**. `XINPUT1_3.dll` is delay-load imported *by
ordinal* (2 `GetState`, 3 `SetState`, 4 `GetCapabilities`, 5 `XInputEnable`), and DirectInput8
is only ever used to create `GUID_SysMouse` and `GUID_SysKeyboard`. A static import table
cannot see a delay-load, which is how this was wrong for a long time.

The netcode presents a synthetic 12-byte `XINPUT_GAMEPAD` at the device seam and lets the
engine derive its eleven-field input window itself. It does not write that window. The earlier
approach did, and could not be made correct: `orig_input_dispatch` derives the edge fields from
the local hardware read *before* any post-hoc write lands. That is a write-ordering defect, not
a field-coverage one, and adding fields never fixes it.

Consequence worth knowing up front: **button configuration is a determinism gate.** Two peers
with different pad bindings are running two different games.

---

## Netcode

`net_transport` is a single nonblocking UDP socket with a GGPO-shaped message set, pumped from
`hk_main_proc` so it stays on the deterministic main thread — no network thread by design.
Above it: epoch agreement so both peers share a frame 0, input delay sized from handshake RTT,
ack-based retransmission, GGPO TimeSync frame-advantage give-back, and a prediction barrier.

`net_engine_arm` exists because arming a rollback engine on two machines at two different
frames means two different baselines, which is the one thing a rollback engine must never have.
One keypress schedules the arm a few frames ahead on both peers, on the same net-frame, and
re-sends while pending so a dropped datagram cannot leave the sides disagreeing.

---

## Reading order

The headers carry the reasoning — each one states the problem before the API. Roughly:

1. `src/arena.h` — the arena, the hooks, the A/B switches
2. `src/edge_break.h` — the complete edge detector, and why sampling can't work
3. `src/dynamic_restore.h` — the sparse override registry
4. `src/idspine.h` — birth stamps and the impostor problem
5. `src/byid.h` — restore-by-identity, and where it is authoritative vs shadow
6. `src/dinput_probe.h` — the device seam
7. `src/net_input.h`, `src/net_transport.h` — the wire

`src/resim.cpp` is the frame loop and the rollback driver. It is the biggest file and the
least tidy; it grew across the whole project.

---

## Terms used in the code

A few coined words survive because they name things that have no standard name here. Each is
defined where it is introduced; collected:

| term | meaning |
|---|---|
| **arena** | the 2GB reservation every engine allocation is redirected into |
| **husk** | a freed block the quarantine still holds, so its slab cannot be reused inside the rollback window |
| **spine** (`idspine`, `rdspine`) | the per-block birth/death stamp tables, keyed on allocator block base |
| **seam** | the point where a subsystem's input enters the engine — the XInput ordinals for pads |
| **carrier** | an object type whose pointer fields are restored by identity rather than by byte |
| **edge** | a pointer field, viewed as a graph edge from holder to referent |
| **sever** | writing 0 into a holder's edge whose referent is dead, so the engine's own null checks handle it |
| **windowed restore** | reverting only the dirty window of pages rather than the whole arena |
| **FLIST-UNIT** | the free-list captured as one unit under the allocator's lock and replayed verbatim |
| **oracle** | a read-only determinism check (e.g. `gp_crc`) that says whether a replay diverged |

---

## Build

WSL driving Windows MinGW-w64, producing `dinput8.dll` next to the game exe.

```
./build.sh
```

`build.sh` has hardcoded paths for this machine (`MINGW_DIR`, `GAME_DIR`, the P2/P3 test
copies). Point them at your own before running. There is no cmake; the link line is literal
and lives in `build.sh`.

Hotkeys once injected: **F5** arm the rollback engine, **F6** force a manual rollback,
**Numpad8** toggle netplay-lean (strips rollback-path detectors, leaves every mechanism in
place). `resim.cpp` has ~26 debug keys in total.

### The binary this targets

The reverse engineering is against the **2017 build, md5 `fa50bd07`**. The game has since been
patched and the addresses in `addr::resolve` will not match a current install. Block the Steam
auto-update and never run Verify Integrity on a working copy. Addresses in the code use a
`0x140000000`-based convention that `addr::resolve` rebases at runtime.

---

## What is actually true right now

Working:

- rollback fires in live netplay, depths 4–6 observed
- the four crash families found so far (use-after-free, torn free-list, audio, slab reuse) are eliminated by construction, not by guards
- the device-seam input path mirrors inputs with no mispredicts on same-machine twins
- long runs (100k+ frames) complete without a crash

Not working, and not hidden:

- **peer drift causes one-directional input loss**, reproducible around stage select — one side
  stops receiving while the other is fine
- **no cross-machine desync detection.** There is a CRC, but it covers 19 curated fighter
  segments and no spawned-layer state, so it cannot see the desyncs that actually happen
- **resim costs ~12.7ms/frame.** That is the number that decides whether this is a real netcode
  or a demo, and it is currently too slow
- hole punching fails on symmetric NAT; the relay is the path that works
- `dynamic_restore` is a skeleton — the registry exists, the inferred descriptors do not
- `idspine` is shadow-only; nothing restores by stamp yet

The gap between "rolls back" and "holds a match together" is desync detection and resim cost,
in that order.

---

## Not in this repo

`.gitignore` keeps this to buildable source. Excluded: the Ghidra project and analysis dumps,
the generated schema tables, run logs, and the design/patchnote markdown (`PATCHNOTES.md`
alone is 832KB of working journal). Ask if you want any of it — most of the reasoning that
isn't in the headers is in there.
