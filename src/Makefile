# SPDX-License-Identifier: GPL-2.0-or-later

PROGRAM:=mldspy
OBJECTS:=mldspy.o log.o misc.o
LIBS:=-lrt -lncurses -ltinfo

.PHONY:		all clean realclean

all:		$(PROGRAM)

$(PROGRAM):	$(OBJECTS)
		$(CC) $(LDFLAGS) -o $(PROGRAM) $(OBJECTS) $(LIBS)

err.o:		err.c err.h

mldspy.o:	mldspy.c mldspy.h

log.o:		log.c log.h

misc.o:		misc.c misc.h

clean:
		rm -f *.o

realclean:
		rm -f *.o $(PROGRAM)

install:	all
		install -d $(BIN_PATH)
		install $(PROGRAM) $(BIN_PATH)/
