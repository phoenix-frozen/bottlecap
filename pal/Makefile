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
CFLAGS += -fno-common -fno-strict-aliasing
CFLAGS += -fomit-frame-pointer
CFLAGS += -I$(CURDIR)/../common -I$(CURDIR)/../include -I$(CURDIR)/../extra -I$(CURDIR)/../tsm -I$(CURDIR)/libs
CFLAGS += -msoft-float
CFLAGS += -fno-jump-tables
CFLAGS += -fno-stack-protector
all: CFLAGS += -fno-builtin -I$(CURDIR)/rte

CFLAGS += -DnotPERFCRIT
CFLAGS += -DMIN_LOG_LEVEL=1
test: CFLAGS += -DBOTTLE_CAP_TEST

AFLAGS += -D__ASSEMBLY__
AFLAGS += -I$(CURDIR)/../common -I$(CURDIR)/../include -I$(CURDIR)/../extra -I$(CURDIR)/../tsm -I$(CURDIR)/libs
all: AFLAGS += -I$(CURDIR)/rte

LDFLAGS	+= -melf_i386

TARGET := $(CURDIR)/pal
TARGET_LDS := $(CURDIR)/rte/pal.ld


C_SRCS := $(wildcard $(CURDIR)/*.c)
C_SRCS += $(wildcard $(CURDIR)/bottlecap/*.c)
C_SRCS += $(wildcard $(CURDIR)/libs/*.c)
TEST_C_SRCS := $(C_SRCS)
C_SRCS += $(wildcard $(CURDIR)/rte/*.c)

S_SRCS := $(wildcard $(CURDIR)/*.S)
S_SRCS += $(wildcard $(CURDIR)/bottlecap/*.S)
S_SRCS += $(wildcard $(CURDIR)/libs/*.S)
TEST_S_SRCS := $(S_SRCS)
S_SRCS += $(wildcard $(CURDIR)/rte/*.S)

HDRS   := $(wildcard $(CURDIR)/*.h)
HDRS   += $(wildcard $(CURDIR)/../common/*.h)
HDRS   += $(wildcard $(CURDIR)/bottlecap/*.h)
HDRS   += $(wildcard $(CURDIR)/libs/*.h)
HDRS   += $(wildcard $(CURDIR)/rte/*.h)

OBJS := $(S_SRCS:.S=.o) $(C_SRCS:.c=.o)
TEST_OBJS := $(TEST_S_SRCS:.S=.o) $(TEST_C_SRCS:.c=.o)

BUILD_DEPS := $(CURDIR)/Makefile

all: $(TARGET).bin

test: $(TARGET).test.elf

$(TARGET).bin: $(OBJS) $(TARGET).elf
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) \
	    -o $(@D)/$(@F) --oformat binary

$(TARGET).elf: $(OBJS) $(TARGET_LDS)
	@echo "------------------"
	echo $(AFLAGS)
	@echo "------------------"
	echo $(CFLAGS)
	@echo "------------------"
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) \
	    -o $(@D)/$(@F)

$(TARGET).test.elf: $(TEST_OBJS)
	@echo "------------------"
	echo $(AFLAGS)
	@echo "------------------"
	echo $(CFLAGS)
	@echo "------------------"
	$(LD) $(LDFLAGS) $(TEST_OBJS) \
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
