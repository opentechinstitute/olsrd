SRC = regcomp.c regerror.c regexec.c regfree.c 
OBJ = $(SRC:.c=.o)
INCLUDES = -I. -I..

CFLAGS := -O2 -D_FORTIFY_SOURCE=2
CFLAGS += -fPIC

all: $(REGEX_LIB)

.c.o:
ifeq ($(VERBOSE),0)
	@echo "[CC] $<"
	@$(CC) $(INCLUDES) $(CFLAGS) $(CPPFLAGS) -c $< -o $@
else
	$(CC) $(INCLUDES) $(CFLAGS) $(CPPFLAGS) -c $< -o $@
endif

$(REGEX_LIB): $(OBJ)
	$(AR) rcs $(REGEX_LIB) $(OBJ)

clean:
	rm -f $(OBJ) $(REGEX_LIB)
