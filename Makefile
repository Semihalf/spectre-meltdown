CFLAGS  += -Wall -O3 -g -Werror
LDFLAGS +=
PROG     = spectre-meltdown-99

OBJS = $(PROG).o
$(PROG): $(OBJS)
	cc -o ${PROG} ${OBJS} ${LDFLAGS}
clean:
	rm -f $(PROG) $(OBJS)
