include Makefile.inc

TOPDIR = ../..
include $(TOPDIR)/Makefile.inc


#CFLAGS += -DPUD_DUMP_GPS_PACKETS_RX_NON_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_UPLINK

#CFLAGS += -DPUD_DUMP_GPS_PACKETS_RX_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_NON_OLSR

#CFLAGS += -DPUD_DUMP_AVERAGING
#CFLAGS += -DPUD_DUMP_DEDUP


CFLAGS += -Werror -D_GNU_SOURCE


VERSION_FILE = ./src/version.h

LIBS += -lnmea -lm


ifneq ($(OS),linux)

default_target install clean:
	@echo "*** $(PLUGIN_NAME) plugin only supported on Linux, sorry!"

else

all: default_target

default_target: version $(PLUGIN_FULLNAME)

$(PLUGIN_FULLNAME): $(OBJS) version-script.txt
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) -o $(PLUGIN_FULLNAME) $(OBJS) $(LIBS)


.PHONY:	version install uninstall clean dist distclean doc doc-clean

version: Makefile scripts/makeVersionH
	@echo "[$(VERSION_FILE)]"
	@./scripts/makeVersionH "$(VERSION_FILE)" "$(PLUGIN_VER)"

install: $(PLUGIN_FULLNAME)
	$(INSTALL_LIB)
	$(STRIP) "$(LIBDIR)/$(PLUGIN_FULLNAME)"

uninstall:
	rm -f "$(LIBDIR)/lib$(PLUGIN_NAME).so" "$(LIBDIR)/$(PLUGIN_NAME)"
	$(UNINSTALL_LIB)

clean: doc-clean
	@echo "[$@]"
	@rm -f $(OBJS) $(SRCS:%.c=%.d) "$(PLUGIN_FULLNAME)"

dist:				distclean
distclean:			clean

doc:
	@$(MAKE) -C doc all

doc-clean:
	@$(MAKE) -C doc clean

endif
