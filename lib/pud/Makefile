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


VERSION_FILE = ./src/version.h

LIBS += -lnmea -lm


ifneq ($(OS),linux)

default_target install clean:
	@echo "*** $(PLUGIN_NAME) plugin only supported on Linux, sorry!"

else

all: default_target

default_target: $(VERSION_FILE) $(PLUGIN_FULLNAME)

$(PLUGIN_FULLNAME): $(OBJS) version-script.txt
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) -o $(PLUGIN_FULLNAME) $(OBJS) $(LIBS)

$(VERSION_FILE): Makefile scripts/makeVersionH
	@echo "[$@]"
	@./scripts/makeVersionH "$@" "$(PLUGIN_VER)"


.PHONY:	install uninstall clean dist distclean doc doc-clean

install: $(PLUGIN_FULLNAME)
	$(INSTALL_LIB)
	$(STRIP) "$(LIBDIR)/$(PLUGIN_FULLNAME)"
	ln -sf "$(PLUGIN_FULLNAME)" "$(LIBDIR)/$(PLUGIN_NAME)"
	ln -sf "$(PLUGIN_FULLNAME)" "$(LIBDIR)/lib$(PLUGIN_NAME).so"

uninstall:
	rm -f "$(LIBDIR)/lib$(PLUGIN_NAME).so" "$(LIBDIR)/$(PLUGIN_NAME)"
	$(UNINSTALL_LIB)

clean: doc-clean
	@echo "[$@]"
	@rm -f $(OBJS) $(SRCS:%.c=%.d) "$(PLUGIN_FULLNAME)" "$(VERSION_FILE)"

dist:				distclean
distclean:			clean

doc:
	@$(MAKE) -C doc all

doc-clean:
	@$(MAKE) -C doc clean

endif
