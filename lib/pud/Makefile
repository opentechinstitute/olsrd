include Makefile.inc

TOPDIR = ../..
include $(TOPDIR)/Makefile.inc


#CFLAGS += -DPUD_DUMP_GPS_PACKETS_RX_NON_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_OLSR

#CFLAGS += -DPUD_DUMP_GPS_PACKETS_RX_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_NON_OLSR

#CFLAGS += -DPUD_DUMP_AVERAGING
#CFLAGS += -DPUD_DUMP_DEDUP


CFLAGS += -Werror -D_GNU_SOURCE


LIBS += -lnmea -lm
PUD_DOC_DIR = ./doc


ifneq ($(OS),linux)

default_target install clean:
	@echo "*** $(PLUGIN_NAME) plugin only supported on Linux, sorry!"

else

default_target: version $(PLUGIN_FULLNAME)

version: Makefile scripts/makeVersionH
	./scripts/makeVersionH "./src/version.h" "$(PLUGIN_VER)" 

$(PLUGIN_FULLNAME): $(OBJS) version-script.txt
	$(CC) $(LDFLAGS) -o $(PLUGIN_FULLNAME) $(OBJS) $(LIBS)

.PHONY:	install uninstall clean dist distclean doc doc-clean

install:	$(PLUGIN_FULLNAME)
	$(STRIP) $(PLUGIN_FULLNAME)
	$(INSTALL_LIB)

uninstall:
	$(UNINSTALL_LIB)

clean: doc-clean
	rm -f $(OBJS) $(SRCS:%.c=%.d) $(PLUGIN_FULLNAME) "./src/version.h"

dist:				distclean
distclean:			clean

doc:
	$(MAKE) -C doc all

doc-clean:
	$(MAKE) -C doc clean

endif
