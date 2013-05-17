
OLSRD_PLUGIN =	true
PLUGIN_NAME =	olsrd_dnssd
PLUGIN_VER =	0.1.2

TOPDIR = ../..
include $(TOPDIR)/Makefile.inc

LIBS +=	$(OS_LIB_PTHREAD) -lldns

# Must be specified along with -lpthread on linux
CPPFLAGS += $(OS_CFLAG_PTHREAD)

ifneq ($(OS),linux)

default_target install clean:
	@echo "*** dnssd Plugin only supported on Linux, sorry!"

else

default_target: $(PLUGIN_FULLNAME)

$(PLUGIN_FULLNAME): $(OBJS) version-script.txt
		@echo "[LD] $@"
		$(CC) $(LDFLAGS) -o $(PLUGIN_FULLNAME) $(OBJS) $(LIBS)

install:	$(PLUGIN_FULLNAME)
		$(STRIP) $(PLUGIN_FULLNAME)
		$(INSTALL_LIB)

uninstall:
		$(UNINSTALL_LIB)

clean:
		rm -f $(OBJS) $(SRCS:%.c=%.d) $(PLUGIN_FULLNAME)

endif
