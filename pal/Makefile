# Makefile made with help from http://www.hsrl.rutgers.edu/ug/make_help.html
# $@ is the name of the file to be made.
# $? is the names of the changed dependents.
# $< the name of the related file that caused the action.
# $* the prefix shared by target and dependent files.

.PHONY: all clean test

CC=gcc
RM=rm -f
AS=as
AR=ar
LD=ld

CFLAGS := -Wall -Werror -O2 -std=gnu99 -m32 -march=i686
CFLAGS += -fno-builtin -fno-common -fno-strict-aliasing
CFLAGS += -fomit-frame-pointer
CFLAGS += -I$(CURDIR)/../common -I$(CURDIR)/../include -I$(CURDIR)/../extra -I$(CURDIR)/../tsm -I $(CURDIR)/rte
CFLAGS += -msoft-float
CFLAGS += -fno-jump-tables
CFLAGS += -fno-stack-protector

CFLAGS += -DnotPERFCRIT
CFLAGS += -DMIN_LOG_LEVEL=1

AFLAGS += -D__ASSEMBLY__
AFLAGS += -I$(CURDIR)/../common -I$(CURDIR)/../include -I$(CURDIR)/../extra -I$(CURDIR)/../tsm

LDFLAGS	+= -melf_i386

TARGET := $(CURDIR)/pal
TARGET_LDS := $(CURDIR)/rte/pal.ld


C_SRCS := $(wildcard $(CURDIR)/*.c)
C_SRCS += $(wildcard $(CURDIR)/bottlecap/*.c)
C_SRCS += $(wildcard $(CURDIR)/rte/*.c)

S_SRCS := $(wildcard $(CURDIR)/*.S)
S_SRCS += $(wildcard $(CURDIR)/bottlecap/*.S)
S_SRCS += $(wildcard $(CURDIR)/rte/*.S)

HDRS   := $(wildcard $(CURDIR)/*.h)
HDRS   += $(wildcard $(CURDIR)/../common/*.h)
HDRS   += $(wildcard $(CURDIR)/bottlecap/*.h)
HDRS   += $(wildcard $(CURDIR)/rte/*.h)

OBJS := $(S_SRCS:.S=.o) $(C_SRCS:.c=.o)

BUILD_DEPS := $(CURDIR)/Makefile

all: $(TARGET).bin


test: $(TARGET).elf
test: CFLAGS := -Wall -Werror -O2 -std=gnu99 -m32 -march=i686
test: CFLAGS += -I$(CURDIR)/../common -I$(CURDIR)/../include -I$(CURDIR)/../extra -I$(CURDIR)/../tsm
test: CFLAGS += -msoft-float
test: CFLAGS += -fno-jump-tables
test: CFLAGS += -fno-stack-protector
test: CFLAGS += -DnotPERFCRIT
test: CFLAGS += -DMIN_LOG_LEVEL=1
test: CFLAGS += -DBOTTLECAP_TEST_HARNESS


$(TARGET).bin: $(OBJS) $(TARGET).elf
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) \
	    -o $(@D)/$(@F) --oformat binary

$(TARGET).elf: $(OBJS) $(TARGET_LDS)
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) \
	    -o $(@D)/$(@F)

clean:
	$(RM) $(TARGET).bin $(TARGET).elf $(OBJS)

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.S $(HDRS) $(BUILD_DEPS)
	$(CC) $(AFLAGS) $(CFLAGS) -c $< -o $@

%.i : %.c $(HDRS) $(BUILD_DEPS)
	$(CPP) $(CFLAGS) $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s : %.S $(HDRS)  $(BUILD_DEPS)
	$(CPP) $(AFLAGS) $< -o $@
