/* SPDX-License-Identifier: GPL-2.0-or-later 
 * Copyright (c) 2019 Brett Sheffield <brett@gladserv.com> */

#include <curses.h>

#define PROGRAM_NAME "mldspy"
#define PROGRAM_VERSION "0.0.0-pre0"

enum {
	WHITE_ON_BLACK = 1,
	BLACK_ON_WHITE,
	YELLOW_ON_BLACK,
	GREEN_ON_BLACK,
	RED_ON_BLACK,
};

WINDOW *win_stat;
WINDOW *win_logs;
