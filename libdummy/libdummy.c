
// SPDX-License-Identifier: MIT
#include "libdummy.h"
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_dummy
// You must define __NR_dummy to the number you assigned in your kernel.
// As a default placeholder, pick an unlikely number in your test kernel.
#define __NR_dummy 451
#endif

void dummy(int id) {
  (void)syscall(__NR_dummy, id);
}
