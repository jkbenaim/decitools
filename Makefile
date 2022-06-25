target = decitools
clones = reset15 bload15 run15 pgo15
objects := deci.o decitools.o hexdump.o mapfile.o

#EXTRAS += -fsanitize=undefined -fsanitize=null -fcf-protection=full -fstack-protector-all -fstack-check -Wimplicit-fallthrough -fanalyzer -Wall -flto

LDFLAGS += ${EXTRAS}
CFLAGS  += -ggdb ${EXTRAS}

.PHONY: all
all:	$(target) $(clones)

.PHONY: clean
clean:
	rm -f $(target) $(clones) $(objects)

decitools: $(objects)

$(clones): decitools
	ln -s $< $@

