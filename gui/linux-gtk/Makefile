CC ?=	gcc

# shows full compiler/linker calls if activated
VERBOSE ?= 0

ifeq ($(VERBOSE),0)
MAKECMDPREFIX = @
else
MAKECMDPREFIX =
endif

# hardening flags: -fPIE -Wl,-z,now -pie
CFLAGS += -O2 -Wall $(shell pkg-config --cflags gtk+-2.0) -fPIE
LDFLAGS += -Wl,-z,now -pie
LIBS := $(shell pkg-config --libs gtk+-2.0) -lm

OBJS=	src/main.o src/interface.o src/callbacks.o src/ipc.o \
	src/packet.o src/nodes.o src/routes.o

all:	olsrd-gui

olsrd-gui:	$(OBJS)
ifeq ($(VERBOSE),0)
	@echo "[LD] $@"
endif
	$(MAKECMDPREFIX)$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
ifeq ($(VERBOSE),0)
	@echo "[CC] $<"
endif
	$(MAKECMDPREFIX)$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

.PHONY: clean install

clean:
	rm -f $(OBJS) olsrd-gui

install:
	mkdir -p "$(DESTDIR)/usr/bin"
	cp ./olsrd-gui "$(DESTDIR)/usr/bin/"
