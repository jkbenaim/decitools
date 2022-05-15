targets = reset15
objects := $(patsubst %.c,%.o,$(wildcard *.c))

libs:=

EXTRAS += -fsanitize=undefined -fsanitize=null -fcf-protection=full -fstack-protector-all -fstack-check -Wimplicit-fallthrough -fanalyzer -Wall

ifdef libs
LDLIBS  += $(shell pkg-config --libs   ${libs})
CFLAGS  += $(shell pkg-config --cflags ${libs})
endif

LDFLAGS += ${EXTRAS}
CFLAGS  += -std=gnu2x -Og -ggdb ${EXTRAS}

.PHONY: all
all:	$(targets)

.PHONY: clean
clean:
	rm -f $(targets) $(objects)

reset15: deci.o hexdump.o reset15.o mapfile.o


