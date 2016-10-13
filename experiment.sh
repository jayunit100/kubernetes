set -x
rm CACH* 

function runMe {
	rm -rf /tmp/perf*test*;   rm -rf /tmp/*scheduler_perf*test* ; df -h ;
	test/integration/scheduler_perf/test-performance.sh ;
	find ./ -name *out
}

function perfResults {
	echo "top100" | go tool pprof test/integration/scheduler_perf/perf.test test/integration/scheduler_perf/prof${PPROF_RUN}.out 
}

export RUN_BENCMARK=true

### EXPERIMENT 1: WITH CACHEING OFF ###
export RECOMPUTE=false
export PPROF_RUN="ENABLED"
runMe
perfResults

### EXPERIMENT 2: WITH CACHEING ON ### 
export RECOMPUTE=true
export PPROF_RUN="DISABLED"
runMe
perfResults


echo " ------------------------------------"
echo "all done !"
ls -altrh test/integration/scheduler_perf/prof*
echo " ------------------------------------"

sleep 1

echo "top100" | go tool pprof test/integration/scheduler_perf/perf.test --base=test/integration/scheduler_perf/profDISABLED.out test/integration/scheduler_perf/profENABLED.out

ls -altrh CACH*
