TARGET = varstored

OBJS :=	guid.o \
	depriv.o \
	handler.o \
	handler_port.o \
	io_port.o \
	mor.o \
	ppi.o \
	ppi_vdata.o \
	varstored.o \
	xapidb.o \
	xapidb-lib.o

CC = gcc

CFLAGS  = -I$(shell pwd)/include

# _GNU_SOURCE for asprintf.
CFLAGS += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_GNU_SOURCE

# EXTRA_CFLAGS can be set through make command line
CFLAGS += $(EXTRA_CFLAGS)

CFLAGS += $$(pkg-config --cflags libxml-2.0)

CFLAGS += -g -O2 -std=gnu99 \
          -Wall \
          -Wstrict-prototypes \
          -Wold-style-declaration \
          -Wmissing-prototypes \
          -Wunused

ifeq ($(shell uname),Linux)
LDLIBS := -lutil -lrt
endif

LDLIBS += -lxenstore \
          -lxenforeignmemory \
          -lxendevicemodel \
          -lxenevtchn \
          -lxentoolcore \
          -lcrypto \
          -lseccomp \
          $$(pkg-config --libs libxml-2.0)

# Get the compiler to generate the dependencies for us.
CFLAGS   += -Wp,-MD,$(@D)/.$(@F).d -MT $(@D)/$(@F)

SUBDIRS  = $(filter-out ./,$(dir $(OBJS) $(LIBS)))
DEPS     = .*.d tools/.*.d

LDFLAGS := -g 

all: $(TARGET) tools

.PHONY: all

$(TARGET): $(LIBS) $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS) $(LDLIBS)

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

TOOLLIBS := -lcrypto -lseccomp $$(pkg-config --libs libxml-2.0)
TOOLOBJS := tools/xapidb-cmdline.o \
            tools/tool-lib.o \
            depriv.o \
            guid.o \
            handler.o \
            mor.o \
            ppi_vdata.o \
            xapidb-lib.o
TOOLS := tools/varstore-ls \
         tools/varstore-get \
         tools/varstore-rm \
         tools/varstore-set \
         tools/varstore-sb-state

tools: $(TOOLS)

.PHONY: tools

$(TOOLS): %: $(TOOLOBJS) %.o
	$(CC) -o $@ $(LDFLAGS) $^ $(TOOLLIBS)

test.o: test.c
	$(CC) -o $@ $(CFLAGS) $$(pkg-config --cflags glib-2.0) -c $<

test: test.o guid.o
	$(CC) -o $@ $(LDFLAGS) $^ -lcrypto $$(pkg-config --libs glib-2.0)

TESTKEYS := testPK.pem testPK.key testcertA.pem testcertA.key testcertB.pem testcertB.key

TESTDEPS := test $(TESTKEYS) guid.o

check: $(TESTDEPS)
	./test

valgrind-check: $(TESTDEPS)
	valgrind --leak-check=full --track-origins=yes ./test

.PHONY: check valgrind-check

AUTHS = PK.auth KEK.auth db.auth
auth: $(AUTHS)

.PHONY: auth

create-auth: create-auth.c guid.o
	$(CC) -o $@ $(CFLAGS) create-auth.c guid.o -Iinclude -lcrypto

%.pem %.key:
	openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$*/" -keyout $*.key -out $*.pem -days 36500 -nodes -sha256

PK.auth: create-auth PK.pem PK.key
	./create-auth -k PK.key -c PK.pem PK PK.auth PK.pem

KEK.auth: create-auth PK.pem PK.key KEK.list
	./create-auth -k PK.key -c PK.pem KEK KEK.auth $$(cat KEK.list)

db.auth: create-auth PK.pem PK.key db.list
	./create-auth -k PK.key -c PK.pem db db.auth $$(cat db.list)

db.list:
	echo certs/MicWinProPCA2011_2011-10-19.pem certs/MicCorUEFCA2011_2011-06-27.pem > $@

KEK.list:
	echo certs/MicCorKEKCA2011_2011-06-24.pem > $@

clean:
	$(foreach dir,$(SUBDIRS),make -C $(dir) clean)
	rm -f $(OBJS)
	rm -f $(DEPS)
	rm -f $(TARGET)
	rm -f TAGS
	rm -f test.o test test.dat
	rm -f $(TESTKEYS)
	rm -f $(AUTHS)
	rm -f create-auth
	rm -f PK.pem PK.key KEK.auth KEK.list db.auth db.list
	rm -f $(TOOLS) $(TOOLOBJS) $(TOOLS:%=%.o)

.PHONY: TAGS
TAGS:
	find . -name \*.[ch] | etags -

-include $(DEPS)

print-%:
	echo $($*)
