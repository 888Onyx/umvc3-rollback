// dinput_probe.h — see dinput_probe.cpp.
#pragma once

namespace dinput_probe {

// Called from our exported DirectInput8Create after the real one succeeds, with the IDirectInput8 it produced.
// Observation only: it patches vtables to log what the game asks for and forwards every call untouched.
void install(void* idirectinput8, const void* riid);

// One-line summary into the log (call sites: the periodic reporter).
void report();

// Call every frame from the input dispatch hook. XINPUT1_3.dll is LoadLibrary'd lazily, and the game enumerates
// its pad slots once, early. Detecting the module only from the periodic reporter meant we first saw it 76s into the
// run — long after that enumeration. The substitution hook has to be installed before the game decides which slots are connected,
// so poll for the module at frame cadence instead. No-op (one bool test) once hooked.
void poll_xinput();

// Read this machine's physical controller, bypassing our own hook (calls the trampoline, so it cannot recurse).
// Scans for the first CONNECTED XInput index rather than assuming 0: a wireless receiver, a plugged-in second
// device, or a pad that enumerated late can easily land on index 1-3, and assuming 0 would read a disconnected
// slot and send NEUTRAL forever — which on the wire looks exactly like "my inputs aren't reaching him".
// Writes 12 bytes (XINPUT_GAMEPAD). Returns false when no pad is connected at all.
bool read_local_pad(void* out12);

// True once the XInput hook is installed and the netcode may drive the pads through it.
bool seam_ready();

// Passive CONTROL-SCHEME DETECTOR
// The button config is a DETERMINISM GATE, not a preference: we ship raw device bits, and the engine permutes them
// into its window vocabulary using that PAD'S config (measured: UP 0x0001->0x0010, A 0x1000->0x4000,...). A peer
// with remapped attack buttons therefore derives different game actions from identical wire bytes, and the sims
// diverge instantly — the same class of failure as a build mismatch.
// We do not need to find where the config is STORED, only what it does, and we sit on both ends of that mapping:
// we know the raw bits we presented and can read the window bits that came out. Learning from single-button frames
// builds the permutation table during natural play, with no probing and no writes.
void observe_mapping(int slot, unsigned short raw_buttons, unsigned int window_held);
unsigned int config_hash(int slot);       // 0 until enough of the table is learned
void config_report();
unsigned short presented_buttons(int slot);

} // namespace dinput_probe
