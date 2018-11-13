TARGET = varstored

OBJS :=	guid.o \
	handler.o \
	io_port.o \
	varstored.o \
	xapidb.o \
	xapidb-lib.o

CFLAGS  = -I$(shell pwd)/include

# _GNU_SOURCE for asprintf.
CFLAGS += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_GNU_SOURCE

CFLAGS += $$(pkg-config --cflags libxml-2.0)

CFLAGS += -Wall -g -O2

ifeq ($(shell uname),Linux)
LDLIBS := -lutil -lrt
endif

LDLIBS += -lxenstore \
          -lxenctrl \
          -lxenforeignmemory \
          -lxendevicemodel \
          -lxenevtchn \
          -lxentoolcore \
          -lcrypto \
          -lseccomp \
          $$(pkg-config --libs libxml-2.0)

# Get gcc to generate the dependencies for us.
CFLAGS   += -Wp,-MD,$(@D)/.$(@F).d -MT $(@D)/$(@F)

SUBDIRS  = $(filter-out ./,$(dir $(OBJS) $(LIBS)))
DEPS     = .*.d tools/.*.d

LDFLAGS := -g 

all: $(TARGET) tools auth

.PHONY: all

$(TARGET): $(LIBS) $(OBJS)
	gcc -o $@ $(LDFLAGS) $(OBJS) $(LIBS) $(LDLIBS)

%.o: %.c
	gcc -o $@ $(CFLAGS) -c $<

TOOLLIBS := -lcrypto $$(pkg-config --libs libxml-2.0)
TOOLOBJS := tools/xapidb-cmdline.o tools/tool-lib.o guid.o handler.o xapidb-lib.o
TOOLS := tools/varstore-ls tools/varstore-get tools/varstore-rm tools/varstore-set

tools: $(TOOLS)

.PHONY: tools

$(TOOLS): %: $(TOOLOBJS) %.o
	gcc -o $@ $(LDFLAGS) $^ $(TOOLLIBS)

test.o: test.c
	gcc -o $@ $(CFLAGS) $$(pkg-config --cflags glib-2.0) -c $<

test: test.o guid.o
	gcc -o $@ $(LDFLAGS) $^ -lcrypto $$(pkg-config --libs glib-2.0)

TESTKEYS := testPK.pem testPK.key testcertA.pem testcertB.pem testcertB.key

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
	gcc -Wall -o create-auth create-auth.c guid.o -Iinclude -lcrypto

%.pem %.key:
	openssl req -new -x509 -newkey rsa:2048 -subj "/CN=$*/" -keyout $*.key -out $*.pem -days 36500 -nodes -sha256

PK.auth: create-auth PK.pem PK.key
	./create-auth -k PK.key -c PK.pem PK PK.auth PK.pem

KEK.auth: create-auth PK.pem PK.key KEK.list
	./create-auth -k PK.key -c PK.pem KEK KEK.auth $$(cat KEK.list)

db.auth: create-auth PK.pem PK.key db.list
	./create-auth -k PK.key -c PK.pem db db.auth $$(cat db.list)

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
	rm -f PK.pem PK.key
	rm -f $(TOOLS) $(TOOLOBJS) $(TOOLS:%=%.o)

.PHONY: TAGS
TAGS:
	find . -name \*.[ch] | etags -

-include $(DEPS)

print-%:
	echo $($*)
