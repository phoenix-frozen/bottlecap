for i in `seq 1 $1`; do
	echo "run $i..."
	./go.sh
	mkdir $i
	cp flicker.in $i
	mv flicker.out $i
	dmesg |grep PROFILING |tail -n 1 >$i/kmod.txt
	chown -R justin:justin $i
	echo "finished run $i"
done
