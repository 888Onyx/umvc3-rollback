#pragma once

namespace rblog {

void init(const char* filepath);
void write(const char* fmt, ...);
void flush();
void suppress(bool on);
bool is_suppressed();
bool try_lock();   // suspend-safety: hold the log lock across a thread-suspend (see log.cpp)
void lock();
void unlock();

} // namespace rblog
