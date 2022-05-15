targets = decitools reset15 run15 bload15 pgo15
objects := $(patsubst %.c,%.o,$(wildcard *.c))

#EXTRAS += -fsanitize=undefined -fsanitize=null -fcf-protection=full -fstack-protector-all -fstack-check -Wimplicit-fallthrough -fanalyzer -Wall

LDFLAGS += ${EXTRAS}
CFLAGS  += -ggdb ${EXTRAS}

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

pgo15: decitools
	ln -s $< $@

