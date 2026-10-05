/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
    sigset_t current;
    int i;
    assert(argc == 3 && !strcmp(argv[1], "-c"));
    assert(!sigprocmask(SIG_SETMASK, NULL, &current));
    for (i = 1; i < NSIG; i++) assert(sigismember(&current, i) == 0);
    return atoi(argv[2]);
}
