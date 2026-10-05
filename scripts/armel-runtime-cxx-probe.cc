#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <dlfcn.h>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <ctime>
#include <cstdio>
static_assert(sizeof(time_t)==8,"new C++ components require time64");
int main(int argc,char **argv) {
 assert(argc==2);
 void *library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);assert(library);
 auto increment=reinterpret_cast<int(*)()>(dlsym(library,"increment"));
 auto throwing=reinterpret_cast<void(*)()>(dlsym(library,"throw_across_dso"));
 assert(increment && throwing && increment()==20);
 bool caught=false;
 try { throwing(); } catch (const std::runtime_error &e) { caught=!strcmp(e.what(),"gcc15-unwind"); }
 assert(caught);
 std::promise<int> result;auto future=result.get_future();
 std::thread worker([&]{result.set_value(increment());});
 assert(future.get()==20);worker.join();assert(increment()==21);
 std::mutex mutex;std::condition_variable cv;std::unique_lock<std::mutex> lock(mutex);
 assert(cv.wait_for(lock,std::chrono::milliseconds(5))==std::cv_status::timeout);
 assert(dlclose(library)==0);
 puts("ARMEL_GCC15_CXX_TLS_THREAD_DSO_UNWIND_PASS");
 return 0;
}
