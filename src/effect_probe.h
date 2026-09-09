#pragma once
// effect_probe — read-only observe-only probes for the moving-crash family (B integrator + P4 consume leaf).
namespace effect_probe {
void init(bool with_consume);   // SE-table hooks (SE-GUARD + A-vs-D discriminator) always; consume_leaf only if with_consume
void report();   // dump the P4 consume-null tally (latent-vanilla verdict)
}
