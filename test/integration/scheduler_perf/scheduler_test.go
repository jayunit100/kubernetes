/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package benchmark

import (
	"fmt"
	"math"
	"testing"
	"time"

	"k8s.io/kubernetes/plugin/pkg/scheduler/factory"
	"k8s.io/kubernetes/test/integration/framework"
	testutils "k8s.io/kubernetes/test/utils"

	"github.com/golang/glog"
)

const (
	threshold = 100
)

// TestPodsPerNode tests a matrix of pods/node with minQPS.
func TestPodsPerNode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping because we want to run short tests")
	}

	results := map[string]int32{}
	for pods := 1; pods < 2000; pods += 500 {
		for nodes := 1; nodes < 3000; nodes += 500 {
			config := defaultSchedulerBenchmarkConfig(pods, nodes)
			if minQPS := schedulePods(config); minQPS < threshold {
				// TODO, re-enable this threshold once we know what we expect.
				// t.Errorf("Too small pod scheduling throughput for 3k pods. Expected %v got %v", threshold3K, min)
			} else {
				fmt.Printf("Minimal observed throughput for 3k pod test: %v\n", minQPS)
				results[fmt.Sprintf("%v pods, %v nodes minQPS", pods, nodes)] = minQPS
			}
		}
	}
	fmt.Print("Done measuring all scenarios for pods/nodes:")
	fmt.Sprint(results)
}

type testConfig struct {
	numPods                int
	numNodes               int
	nodePreparer           testutils.TestNodePreparer
	podCreator             *testutils.TestPodCreator
	schedulerConfigFactory *factory.ConfigFactory
	destroyFunc            func()
}

func baseConfig() *testConfig {
	schedulerConfigFactory, destroyFunc := mustSetupScheduler()
	return &testConfig{
		schedulerConfigFactory: schedulerConfigFactory,
		destroyFunc:            destroyFunc,
	}
}

func defaultSchedulerBenchmarkConfig(numNodes, numPods int) *testConfig {
	baseConfig := baseConfig()

	nodePreparer := framework.NewIntegrationTestNodePreparer(
		baseConfig.schedulerConfigFactory.Client,
		[]testutils.CountToStrategy{{Count: numNodes, Strategy: &testutils.TrivialNodePrepareStrategy{}}},
		"scheduler-perf-",
	)

	config := testutils.NewTestPodCreatorConfig()
	config.AddStrategy("sched-test", numPods, testutils.NewSimpleWithControllerCreatePodStrategy("rc1"))
	podCreator := testutils.NewTestPodCreator(baseConfig.schedulerConfigFactory.Client, config)

	baseConfig.nodePreparer = nodePreparer
	baseConfig.podCreator = podCreator
	baseConfig.numPods = numPods
	baseConfig.numNodes = numNodes

	return baseConfig
}

// schedulePods schedules specific number of pods on specific number of nodes.
// This is used to learn the scheduling throughput on various
// sizes of cluster and changes as more and more pods are scheduled.
// It won't stop until all pods are scheduled.
// It retruns the minimum of throughput over whole run.
func schedulePods(config *testConfig) int32 {
	defer config.destroyFunc()
	if err := config.nodePreparer.PrepareNodes(); err != nil {
		glog.Fatalf("%v", err)
	}
	defer config.nodePreparer.CleanupNodes()
	config.podCreator.CreatePods()

	prev := 0
	// On startup there may be a latent period where NO scheduling occurs (qps = 0).
	// We are interested in low scheduling rates (i.e. qps=2),
	minQps := int32(math.MaxInt32)
	qps := []int32{}

	// Bake in time for the first pod scheduling event.
	start := time.Now()
	waitForStart := func() {
		for {
			time.Sleep(50 * time.Millisecond)
			scheduled := config.schedulerConfigFactory.ScheduledPodLister.Indexer.List()
			if len(scheduled) > 0 {
				return
			}
		}
	}
	waitForStart()

	// Now that scheduling has started, lets start taking the pulse on how many pods are happening per second.
	for {
		time.Sleep(1000 * time.Millisecond)
		scheduled := config.schedulerConfigFactory.ScheduledPodLister.Indexer.List()
		// There's no point in printing it for the last iteration, as the value is random
		qps = append(qps, int32(len(scheduled)-prev))

		// ignore 0 qps measurements, they are uninteresting.
		// the per-second pods may look something like this.
		// 192 0 0 0 0 0 0 0 946 0 0 0 0 0 0 0
		if currQps := qps[len(qps)-1]; currQps > 0 && currQps < minQps {
			minQps = currQps
		}
		fmt.Printf("%ds\trate: %d\ttotal: %d\n", time.Since(start)/time.Second, qps, len(scheduled))
		prev = len(scheduled)

		// This can potentially affect performance of scheduler, since List() is done under mutex.
		// Listing 10000 pods is an expensive operation, so running it frequently may impact scheduler.
		// TODO: Setup watch on apiserver and wait until all pods scheduled.
		if len(scheduled) >= config.numPods {
			fmt.Printf("Scheduled %v Pods in %v seconds (%v per second on average). min QPS was %v\n",
				config.numPods, int(time.Since(start)/time.Second), config.numPods/int(time.Since(start)/time.Second), minQps)
			// We will be completed when all pods are done being scheduled.
			// return the worst-case-scenario interval that was seen during this time.
			// Note this should never be low due to cold-start, so allow bake in sched time if necessary.
			return minQps
		}
	}
}
