# Makefile made with help from http://www.hsrl.rutgers.edu/ug/make_help.html
# $@ is the name of the file to be made.
# $? is the names of the changed dependents.
# $< the name of the related file that caused the action.
# $* the prefix shared by target and dependent files.

.PHONY: all clean test cscope cscope.files

CC=gcc
RM=rm -f
AS=as
AR=ar
LD=ld

INCLUDES := $(CURDIR)/../common $(CURDIR)/../include $(CURDIR)/../extra $(CURDIR)/../tsm $(CURDIR)/libs $(wildcard $(CURDIR)/libs/*)

CFLAGS := -Wall -Werror -O2 -std=gnu99 -march=i686
CFLAGS += -fno-common -fno-strict-aliasing
CFLAGS += -fomit-frame-pointer
CFLAGS += $(INCLUDES:%=-I%)
CFLAGS += -fno-stack-protector

TARGET := $(CURDIR)/datagen

C_SRCS := $(wildcard $(CURDIR)/*.c)
C_SRCS += $(wildcard $(CURDIR)/libs/*/*.c)

HDRS   := $(wildcard $(CURDIR)/*.h)
HDRS   += $(wildcard $(CURDIR)/../common/*.h)
HDRS   += $(wildcard $(CURDIR)/libs/*/*.h)

OBJS := $(C_SRCS:.c=.o)

BUILD_DEPS := $(CURDIR)/Makefile

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -N $(OBJS) -o $(@D)/$(@F)

clean:
	$(RM) $(TARGET) $(OBJS)

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

cscope.files:
	find `pwd` -iname \*.[chs] >cscope.files
	find `readlink -f ../common` -iname \*.[chs] >>cscope.files

cscope: cscope.files
	cscope -q -b -k

