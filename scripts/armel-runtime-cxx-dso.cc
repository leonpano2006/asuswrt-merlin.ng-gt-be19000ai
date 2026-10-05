#include <stdexcept>
static thread_local int value=19;
extern "C" int increment(void) { return ++value; }
extern "C" void throw_across_dso(void) { throw std::runtime_error("gcc15-unwind"); }
