/* SPDX-License-Identifier: GPL-2.0-or-later 
 * Copyright (c) 2019 Brett Sheffield <brett@gladserv.com> */

#ifndef __ERR_H__
#define __ERR_H__ 1

#include <errno.h>

#define ERROR_CODES(X) \
	X(ERROR_SUCCESS,		"Success") \
	X(ERROR_FAILURE,		"Failure") \
	X(ERROR_MALLOC,			"Memory allocation error") \
	X(ERROR_INVALID_ARGS,		"Invalid command line options") \
	X(ERROR_INVALID_PARAMS,		"Invalid arguments to function") \
	X(ERROR_THREAD_CANCEL,		"Failed to cancel thread") \
	X(ERROR_THREAD_JOIN,		"Failed to join thread") \
	X(ERROR_FILE_OPEN_FAIL,		"Unable to open file") \
	X(ERROR_FILE_STAT_FAIL,		"Unable to stat ile") \
	X(ERROR_MMAP_FAIL,		"Unable to map file")
#undef X

#define ERROR_MSG(name, msg) case name: return msg;
#define ERROR_ENUM(name, msg) name,
enum {
	ERROR_CODES(ERROR_ENUM)
};

/* log message and return code */
int err_log(int level, int e);

/* return human readable error message for e */
char *err_msg(int e);

/* print human readable error, using errsv (errno) or progam defined (e) code */
void err_print(int e, int errsv, char *errstr);

#endif /* __ERR_H__ */
