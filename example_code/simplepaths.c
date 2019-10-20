
#include <stdio.h>

int
main(int argc, char **argv) {
  if (argc != 4) {
    puts("This program requires 4 command line arguments!\n");
    return -1;
  }
  if (argv[1][0] == 'A') {
    puts("X");
  }
  if (argv[2][0] == 'B') {
    puts("Y");
  }
  if (argv[3][0] == 'C') {
    puts("Z");
  }
  return 0;
}

