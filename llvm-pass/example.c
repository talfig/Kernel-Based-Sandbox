
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int foo(const char* path) {
  int fd = open(path, O_RDONLY);
  if (fd >= 0) {
    char buf[16];
    read(fd, buf, sizeof(buf));
  }
  close(fd);
  return 0;
}
