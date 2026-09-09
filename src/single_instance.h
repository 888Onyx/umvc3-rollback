#pragma once
// single_instance.h — netplay infrastructure. The game's WinMain runs a single-instance guard
// (CreateMutexA named-mutex + FindWindowW self-window check, both imported); the SECOND copy sees the first
// and ExitProcess's at ~26ms (before it ever renders) — which blocks P1+P2 from coexisting for the loopback test.
// Our dinput8 DllMain runs before WinMain, so we IAT-patch the exe's CreateMutexA/FindWindowW to neuter the guard.
// Gated on netplay.flag next to the exe: both twins have it (role-suffixed mutex + self-FindWindow null), so they
// coexist; a solo instance without the flag keeps the real named mutex. IAT patch (not MinHook) = loader-lock-safe,
// in place before WinMain.
namespace single_instance {
void install();   // call from DllMain (DLL_PROCESS_ATTACH), after role::init(); no-op unless netplay.flag is present
}
