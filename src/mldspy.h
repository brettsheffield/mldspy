#include <curses.h>

#define PROGRAM_NAME "mldspy"
#define PROGRAM_VERSION "0.0.0-pre0"

enum {
	WHITE_ON_BLACK = 1,
	BLACK_ON_WHITE,
	BLACK_ON_GREEN,
	GREEN_ON_BLACK,
};

WINDOW *win_stat;
WINDOW *win_logs;
