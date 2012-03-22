#!/bin/bash

# Flicker session invocation script for Linux; copes with both AMD and Intel CPUs

if [ ! -r pal.bin ]
then
    echo "No PAL to execute!"
    exit -1
fi

if [ ! -r flicker.in ]
then
    echo "No flicker.in to provide input!"
    exit -1
fi

# stop if anything goes wrong
set -e

# Sync filesystems
echo "Syncing filesystems..."
sync
sync
sync
sync

# Make a temporary ramfs
echo "Mounting tmpfs..."
mkdir -p ramfs
mount -t tmpfs none ramfs

# Bring down eth0
echo "Bringing down eth0..."
ifdown eth0
modprobe -r e1000e

# Remount root FS read-only
echo "Remounting root filesystem read-only..."
mount -fo remount,ro /

# Verify flicker kernel module is installed
if [ `grep flicker /proc/modules | wc -l` = "0" ]
    then
    echo "Inserting flicker.ko module"
    insmod ../kmod/flicker.ko
fi

# Disable (up to 8) APs
for i in `seq 1 9`
  do
  if [ -e /sys/devices/system/cpu/cpu$i ]
      then
      if [ `cat /sys/devices/system/cpu/cpu$i/online` = "1" ]
          then
          echo "Disabling CPU $i"
          echo 0 > /sys/devices/system/cpu/cpu$i/online
      fi
  fi
done

SYSFSPATH=/sys/kernel/flicker

# Try to be CPU-agnostic in this script. ASSUMPTION: There is only
# one SINIT module on the system, it is located in /boot, and it
# contains SINIT in the filename.
SINIT=""
for sinitfile in /boot/*SINIT*
do
    SINIT=$sinitfile
done
if [ -e $SINIT ]
then
    echo "Found SINIT $SINIT"
    # Load ACmod
    echo -n A > $SYSFSPATH/control
    cat $SINIT > $SYSFSPATH/data
    echo -n a > $SYSFSPATH/control
    echo "SINIT $SINIT loaded"
else
    # Could not find SINIT, check for Intel processor
    if [ `grep Intel /proc/cpuinfo | wc -l` -gt 0 ] ; then
        echo "FATAL ERROR: Intel processor detected but no SINIT module found."
        exit
    fi
    # We're still here.  Assume we have an AMD processor and proceed.
    echo "Proceeding for AMD processor"
fi

# Load PAL
echo -n M > $SYSFSPATH/control
cat pal.bin > $SYSFSPATH/data
echo -n m > $SYSFSPATH/control

# Load some test inputs (3 inputs: command 42, and two null-padded strings)
echo -n I > $SYSFSPATH/control
# Try this echo command from the bash prompt and pipe through hd to get:
#00000000  01 00 00 00 ca fe f0 0d  04 00 00 00 de ad be ef  |................|
#echo -ne \\x01\\x00\\x00\\x00\\x0d\\xf0\\xfe\\xca\\x04\\x00\\x00\\x00\\xef\\xbe\\xad\\xde > $SYSFSPATH/data
cat flicker.in > $SYSFSPATH/data
echo -n i > $SYSFSPATH/control

# Launch Flicker session
sleep 1
echo -n G > $SYSFSPATH/control

# Read outputs
echo "Retrieving outputs from Flicker session..."
cat $SYSFSPATH/data > ramfs/flicker.out

rmmod flicker

PCRS=`find /sys -name pcrs`
if [ ! -z $PCRS ]
  then
  echo PCRs found at $PCRS
  grep PCR-17 $PCRS
fi

# Remount root FS read-write
echo "Remounting root filesystem read-write..."
mount -fo remount,rw /

# Copy results out of ramfs
echo "Retrieving results..."
cp ramfs/flicker.out .

# Drop ramfs
echo "Dropping tmpfs..."
umount ramfs
rmdir ramfs

# Bring eth0 back up
echo "Reinitialising network..."
modprobe e1000e

# Re-enable (up to 8) APs
for i in `seq 1 9`
  do
  if [ -e /sys/devices/system/cpu/cpu$i ]
      then
      if [ `cat /sys/devices/system/cpu/cpu$i/online` = "0" ]
          then
          echo "Enabling CPU $i"
          echo 1 > /sys/devices/system/cpu/cpu$i/online
      fi
  fi
done

exit

