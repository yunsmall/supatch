
CFLAGS = -D_GNU_SOURCE -std=c11 -Wall -Wextra -Wno-unused -Wno-unused-parameter
CPPFLAGS += -I../include

SRC += kpatch.c
SRC += kpm.c
SRC += kpextension.c
SRC += rehook.c
SRC += supatch.c

OBJS := $(SRC:.c=.o)

all: kpatch.a kpatch

kpatch: main.o ${OBJS}
	${CC} $(LDFLAGS) -o $@ $^

kpatch.a: ${OBJS}
	${AR} rcs $@ $^

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf build
	rm -rf uapi
	rm -f kpatch
	rm -f *.a 
	find . -name "*.o" | xargs rm -f