# Makefile made with help from http://www.hsrl.rutgers.edu/ug/make_help.html
# $@ is the name of the file to be made.
# $? is the names of the changed dependents.
# $< the name of the related file that caused the action.
# $* the prefix shared by target and dependent files.

.PHONY: all clean cscope
.INTERMEDIATE: cscope.files

CC=gcc
RM=rm -f
AS=as
AR=ar
LD=gcc

INCLUDES := $(CURDIR)/../common $(CURDIR)/../include $(CURDIR)/../extra $(CURDIR)/../tsm $(CURDIR)/libs $(wildcard $(CURDIR)/libs/*)

TARGETS := gencap errcode bottleonly attest expire

CFLAGS := -Wall -O2 -std=gnu99 -march=i686
CFLAGS += -fno-common -fno-strict-aliasing
CFLAGS += -fomit-frame-pointer
CFLAGS += $(INCLUDES:%=-I%)
CFLAGS += -fno-stack-protector

TARGET := $(CURDIR)/datagen

C_SRCS := $(CURDIR)/params.c $(CURDIR)/main.c
C_SRCS += $(wildcard $(CURDIR)/libs/*/*.c)

HDRS   := $(wildcard $(CURDIR)/*.h)
HDRS   += $(wildcard $(CURDIR)/../common/*.h)
HDRS   += $(wildcard $(CURDIR)/libs/*/*.h)

OBJS := $(C_SRCS:.c=.o)

.SECONDARY: $(TARGETS:%=%.o) $(OBJS)

BUILD_DEPS := $(CURDIR)/Makefile

all: $(TARGETS)

clean:
	$(RM) $(TARGETS) $(TARGETS:%=%.o) $(OBJS)

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGETS): %: %.o $(OBJS) $(BUILD_DEPS)
	$(LD) $(LDFLAGS) $(OBJS) $< -o $@

cscope.files:
	find `pwd` -iname \*.[chs] >cscope.files
	find `readlink -f ../common` -iname \*.[chs] >>cscope.files

cscope: cscope.files
	cscope -q -b -k

