#pragma once
// count_drift_census.h — count-drift experiment instrument. MEASURE the native count-gated-unlink guard-skip (the
// a4 count-drift SEED mechanism) so a control run settles whether the seed is resim-timing-induced (OUR environment,
// fixable by quiescing a4-touching workers during resim) or vanilla-latent (an inherited floor). Passive: counts only.
namespace count_drift_census {
void init();     // hook FUN_1404CAA60 (the standalone count-gated unlink); no-op if already armed
void report();   // emit the aggregate guard-skip split (call from the main-thread heartbeat)
}
