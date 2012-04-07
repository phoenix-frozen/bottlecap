REPCOUNT=100

for i in ../io/*.in; do
	SUITE=`basename $i`
	echo "suite $SUITE start"
	cp $i flicker.in
	./bench.sh $REPCOUNT
	mkdir $SUITE
	mv `seq $REPCOUNT |xargs` $SUITE
	mv $SUITE $i.bench
	echo "suite $SUITE done"
done
