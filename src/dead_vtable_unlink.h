#pragma once

// dead_vtable_unlink — dead-vtable entity unlink
// One job: find entities with invalid vtables, remove from all dispatch lists.
// No NULL-SAFE. No gates. No animation rules. The engine handles its own fields.

namespace dead_vtable_unlink {

constexpr int POST_LOAD = 1;
constexpr int POST_RESIM = 2;

void init();
void validate(int phase);

} // namespace dead_vtable_unlink
