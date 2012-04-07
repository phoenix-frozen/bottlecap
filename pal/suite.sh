REPCOUNT=100

for i in ../io/*.in; do
	if [ ! -d $i.bench ]; then
		SUITE=`basename $i`
		echo "suite $SUITE start"
		cp $i flicker.in
		./bench.sh $REPCOUNT
		mkdir $SUITE
		mv `seq $REPCOUNT |xargs` $SUITE
		mv $SUITE $i.bench
		echo "suite $SUITE done"
	fi
done
