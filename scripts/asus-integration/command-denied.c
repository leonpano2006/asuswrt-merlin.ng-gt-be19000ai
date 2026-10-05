/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
int main(int argc, char **argv)
{
        (void)argc;
        fprintf(stderr, "ASUS command '%s' is disabled in this migration profile; use its reviewed native owner.\n", argv[0]);
        return 125;
}
