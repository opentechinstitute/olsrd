LIBRARY_PATH = wireformat
JAVA_PATH = wireformat-java
include $(LIBRARY_PATH)/Makefile.inc
LIBRARY_NAME := $(PROJECT)


include Makefile.inc

TOPDIR = ../..
include $(TOPDIR)/Makefile.inc


#CFLAGS += -DPUD_DUMP_GPS_PACKETS_RX_NON_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_UPLINK
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_DOWNLINK

#CFLAGS += -DPUD_DUMP_GPS_PACKETS_RX_OLSR
#CFLAGS += -DPUD_DUMP_GPS_PACKETS_TX_NON_OLSR

#CFLAGS += -DPUD_DUMP_AVERAGING
#CFLAGS += -DPUD_DUMP_DEDUP


CFLAGS += -Werror -D_GNU_SOURCE


VERSION_FILE = ./src/version.h
LIBRARY_INC = $(LIBRARY_PATH)/include
LIBRARY_LIB = $(LIBRARY_PATH)/lib

CFLAGS += -I $(LIBRARY_INC)
LIBS += -L $(LIBRARY_LIB) -lnmea -lm -l$(LIBRARY_NAME)


# repeat from toplevel Makefile.inc, and adjust: we need the library includes
%.d: %.c
	@$(filter-out $(CCACHE),$(CC)) -M $(strip $(CPPFLAGS)) -I $(LIBRARY_INC) "$<" | sed -e '1s/\($(call quote,$(*F))\.o\)[ :]*/$(call quote,$(*D)/\1 $@: Makefile $(TOPDIR)$(if $(TOPDIR),/)Makefile.inc) /g' >"$@"


ifneq ($(OS),linux)

default_target install clean:
	@echo "*** $(PLUGIN_NAME) plugin only supported on Linux, sorry!"

else

all: default_target

default_target: version $(PLUGIN_FULLNAME)

$(PLUGIN_FULLNAME): library $(OBJS) version-script.txt
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) -o $(PLUGIN_FULLNAME) $(OBJS) $(LIBS)


.PHONY:	version install uninstall clean dist distclean doc doc-clean library library-clean library-doc library-doc-clean

version: Makefile scripts/makeVersionH
	@echo "[$(VERSION_FILE)]"
	@./scripts/makeVersionH "$(VERSION_FILE)" "$(PLUGIN_VER)"

install: all
	@$(MAKE) -C $(LIBRARY_PATH) DESTDIR=$(DESTDIR) install
	$(INSTALL_LIB)
	$(STRIP) "$(LIBDIR)/$(PLUGIN_FULLNAME)"

uninstall:
	@$(MAKE) -C $(LIBRARY_PATH) DESTDIR=$(DESTDIR) uninstall
	rm -f "$(LIBDIR)/lib$(PLUGIN_NAME).so" "$(LIBDIR)/$(PLUGIN_NAME)"
	$(UNINSTALL_LIB)
	rmdir -v -p --ignore-fail-on-non-empty "$(LIBDIR)"

clean:
	@echo "[$@]"
	@rm -f $(OBJS) $(SRCS:%.c=%.d) "$(PLUGIN_FULLNAME)"
	@$(MAKE) -C doc clean
	@$(MAKE) -C $(LIBRARY_PATH) clean
	@$(MAKE) -C $(JAVA_PATH) clean

dist:				distclean
distclean:			clean


doc:
	@$(MAKE) -C doc all
	@$(MAKE) -C $(LIBRARY_PATH) doc
	@$(MAKE) -C $(JAVA_PATH) doc

library:
	@$(MAKE) -C $(LIBRARY_PATH) all


java:
	@$(MAKE) -C $(JAVA_PATH) all

java-install: java
	@$(MAKE) -C $(JAVA_PATH) DESTDIR=$(DESTDIR) install

java-uninstall:
	@$(MAKE) -C $(JAVA_PATH) DESTDIR=$(DESTDIR) uninstall

endif
