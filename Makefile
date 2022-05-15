targets = decitools reset15 run15 bload15
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

decitools: deci.o hexdump.o decitools.o mapfile.o

reset15: decitools
	ln -s $< $@

run15: decitools
	ln -s $< $@

bload15: decitools
	ln -s $< $@

