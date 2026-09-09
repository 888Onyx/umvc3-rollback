#pragma once
// render_edge_probe — read-only parent->freed-child diagnostic. Buckets sRender's two no-null-guard lists for
// DANGLING entries (entry -> object whose first qword is not a module vtable). The render present/retirement walks
// (0x14053A4B6 present, 0x14053A5D7 retirement) deref these with no null/validity guard => the kept-live sRender ->
// reverted/reused referent crash. Counting where the danglers are (which list) and when (POST_LOAD vs post-resim)
// tells the eventual count-coherent compaction sever which list + which phase to act on. Writes nothing.
namespace render_edge_probe {
void probe(const char* tag);   // call at POST_LOAD and post-resim
}
