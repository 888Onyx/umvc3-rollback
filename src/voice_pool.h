#pragma once

namespace voice_pool {
    void init();              // MH_CreateHook all destruction sites (caller enables)
    void on_frame(int frame); // flush old entries, called each normal frame
    void pause_flush();       // call at rollback start
    void resume_flush();      // call after resim ends
    void on_rollback(int target_frame); // re-stamp every pooled entry's flush timer (extends the reprieve across the resim window)
    void flush_all();          // immediately destroy every pooled voice (call when the engine goes off)
}
