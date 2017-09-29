CC             := gcc
SHELL          := /bin/bash
TARGET         := generate
PBCDIR         := ../pbc-0.5.14
GMPDIR         := ../gmp-6.1.2
INCLUDEDIRS    := $(PBCDIR)/include/ $(GMPDIR)
INCLUDE        := $(addprefix -I,$(INCLUDEDIRS))
LIBDIRS        := $(PBCDIR)/.libs $(GMPDIR)/.libs
LIBS           := pbc gmp
LINK           := $(addprefix -L,$(LIBDIRS)) \
                  $(addprefix -l,$(LIBS))
DEPENDENCIES   := 0

ifeq ($(DEPENDENCIES),1)
all: pbc gmp
endif

all: $(TARGET).c
	$(CC) $(TARGET).c -o $(TARGET) $(INCLUDE) $(LINK) -static

gmp:
	cd $(GMPDIR) && $(MAKE) clean || true && ./configure && $(MAKE)

pbc: gmp
	cd $(PBCDIR) && $(MAKE) clean || true && LDFLAGS="-L$(realpath $(GMPDIR)/.libs/)" CPPFLAGS="-I$(realpath $(GMPDIR))" ./configure && $(MAKE)

clean:
	rm -rf $(TARGET) a_224_1024.param a_256_1536.txt 

.PHONY: all gmp pbc clean

