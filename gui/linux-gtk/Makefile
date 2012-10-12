CC ?=	gcc

# hardening flags: -fPIE -Wl,-z,now -pie
CFLAGS += -O2 -Wall `pkg-config --cflags gtk+-2.0` -fPIE
LDFLAGS += -Wl,-z,now -pie
LIBS := `pkg-config --libs gtk+-2.0` -lm

OBJS=	src/main.o src/interface.o src/callbacks.o src/ipc.o \
	src/packet.o src/nodes.o src/routes.o

all:	olsrd-gui

olsrd-gui:	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) olsrd-gui

install:
	mkdir -p ${DESTDIR}/usr/bin
	cp ./olsrd-gui ${DESTDIR}/usr/bin/
