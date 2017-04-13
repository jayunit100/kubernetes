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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/test/integration/framework"
	testutils "k8s.io/kubernetes/test/utils"

	"flag"
	"github.com/golang/glog"
	"k8s.io/kubernetes/plugin/pkg/scheduler"
)

const (
	warning3K    = 100
	threshold3K  = 30
	threshold30K = 30
	threshold60K = 30
)

// TODO: Need a way to eliminate these.
var nodes, pods int

// TestSchedule100Node3KNodeAffinityPods schedules 3k pods using Node affinity on 100 nodes.
func TestSchedule100Node3KNodeAffinityPods(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping because we want to run short tests")
	}

	config := baseConfig()
	config.numNodes = 100
	config.numPods = 3000

	// number of Node-Pod sets with Pods NodeAffinity matching given Nodes.
	numGroups := 10
	nodeAffinityKey := "kubernetes.io/sched-perf-node-affinity"

	nodeStrategies := make([]testutils.CountToStrategy, 0, 10)
	for i := 0; i < numGroups; i++ {
		nodeStrategies = append(nodeStrategies, testutils.CountToStrategy{
			Count:    config.numNodes / numGroups,
			Strategy: testutils.NewLabelNodePrepareStrategy(nodeAffinityKey, fmt.Sprintf("%v", i)),
		})
	}
	config.nodePreparer = framework.NewIntegrationTestNodePreparer(
		config.schedulerSupportFunctions.GetClient(),
		nodeStrategies,
		"scheduler-perf-",
	)

	podCreatorConfig := testutils.NewTestPodCreatorConfig()
	for i := 0; i < numGroups; i++ {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "sched-perf-node-affinity-pod-",
			},
			Spec: testutils.MakePodSpec(),
		}
		pod.Spec.Affinity = &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{
						{
							MatchExpressions: []v1.NodeSelectorRequirement{
								{
									Key:      nodeAffinityKey,
									Operator: v1.NodeSelectorOpIn,
									Values:   []string{fmt.Sprintf("%v", i)},
								},
							},
						},
					},
				},
			},
		}

		podCreatorConfig.AddStrategy("sched-perf-node-affinity", config.numPods/numGroups,
			testutils.NewCustomCreatePodStrategy(pod),
		)
	}
	config.podCreator = testutils.NewTestPodCreator(config.schedulerSupportFunctions.GetClient(), podCreatorConfig)

	if min := schedulePods(config); min < threshold30K {
		t.Errorf("Too small pod scheduling throughput for 30k pods. Expected %v got %v", threshold30K, min)
	} else {
		fmt.Printf("Minimal observed throughput for 30k pod test: %v\n", min)
	}
}

// TestSchedule1000Node30KPods schedules 30k pods on 1000 nodes.
func TestSchedule1000Node30KPods(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping because we want to run short tests")
	}

	config := defaultSchedulerBenchmarkConfig(1000, 30000)
	if min := schedulePods(config); min < threshold30K {
		t.Errorf("To small pod scheduling throughput for 30k pods. Expected %v got %v", threshold30K, min)
	} else {
		fmt.Printf("Minimal observed throughput for 30k pod test: %v\n", min)
	}
}

// TestSchedule2000Node60KPods schedules 60k pods on 2000 nodes.
// This test won't fit in normal 10 minutes time window.
// func TestSchedule2000Node60KPods(t *testing.T) {
// 	if testing.Short() {
// 		t.Skip("Skipping because we want to run short tests")
// 	}
// 	config := defaultSchedulerBenchmarkConfig(2000, 60000)
// 	if min := schedulePods(config); min < threshold60K {
// 		t.Errorf("To small pod scheduling throughput for 60k pods. Expected %v got %v", threshold60K, min)
// 	} else {
// 		fmt.Printf("Minimal observed throughput for 60k pod test: %v\n", min)
// 	}
// }

type testConfig struct {
	numPods                   int
	numNodes                  int
	nodePreparer              testutils.TestNodePreparer
	podCreator                *testutils.TestPodCreator
	schedulerSupportFunctions scheduler.Configurator
	destroyFunc               func()
}

func baseConfig() *testConfig {
	schedulerConfigFactory, destroyFunc := mustSetupScheduler()
	return &testConfig{
		schedulerSupportFunctions: schedulerConfigFactory,
		destroyFunc:               destroyFunc,
	}
}

func defaultSchedulerBenchmarkConfig(numNodes, numPods int) *testConfig {
	baseConfig := baseConfig()

	nodePreparer := framework.NewIntegrationTestNodePreparer(
		baseConfig.schedulerSupportFunctions.GetClient(),
		[]testutils.CountToStrategy{{Count: numNodes, Strategy: &testutils.TrivialNodePrepareStrategy{}}},
		"scheduler-perf-",
	)

	config := testutils.NewTestPodCreatorConfig()
	config.AddStrategy("sched-test", numPods, testutils.NewSimpleWithControllerCreatePodStrategy("rc1"))
	podCreator := testutils.NewTestPodCreator(baseConfig.schedulerSupportFunctions.GetClient(), config)

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
// It returns the minimum of throughput over whole run.
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
	start := time.Now()

	// Bake in time for the first pod scheduling event.
	for {
		time.Sleep(50 * time.Millisecond)
		scheduled, err := config.schedulerSupportFunctions.GetScheduledPodLister().List(labels.Everything())
		if err != nil {
			glog.Fatalf("%v", err)
		}
		// 30,000 pods -> wait till @ least 300 are scheduled to start measuring.
		// TODO Find out why sometimes there may be scheduling blips in the beggining.
		if len(scheduled) > config.numPods/100 {
			break
		}
	}
	// map minimum QPS entries in a counter, useful for debugging tests.
	qpsStats := map[int]int{}

	// Now that scheduling has started, lets start taking the pulse on how many pods are happening per second.
	for {
		// This can potentially affect performance of scheduler, since List() is done under mutex.
		// Listing 10000 pods is an expensive operation, so running it frequently may impact scheduler.
		// TODO: Setup watch on apiserver and wait until all pods scheduled.
		scheduled, err := config.schedulerSupportFunctions.GetScheduledPodLister().List(labels.Everything())
		if err != nil {
			glog.Fatalf("%v", err)
		}

		// We will be completed when all pods are done being scheduled.
		// return the worst-case-scenario interval that was seen during this time.
		// Note this should never be low due to cold-start, so allow bake in sched time if necessary.
		if len(scheduled) >= config.numPods {
			fmt.Printf("Scheduled %v Pods in %v seconds (%v per second on average). min QPS was %v\n",
				config.numPods, int(time.Since(start)/time.Second), config.numPods/int(time.Since(start)/time.Second), minQps)
			return minQps
		}

		// There's no point in printing it for the last iteration, as the value is random
		qps := len(scheduled) - prev
		qpsStats[qps] += 1
		if int32(qps) < minQps {
			minQps = int32(qps)
		}
		fmt.Printf("%ds\trate: %d\ttotal: %d (qps frequency: %v)\n", time.Since(start)/time.Second, qps, len(scheduled), qpsStats)
		prev = len(scheduled)
		time.Sleep(1 * time.Second)
	}
}

func (nodeAffinity *NodeAffinity) mutateNode(numNodes int) []testutils.CountToStrategy {
	numGroups := nodeAffinity.numGroups
	nodeAffinityKey := nodeAffinity.nodeAffinityKey
	nodeStrategies := make([]testutils.CountToStrategy, 0, 10)
	for i := 0; i < numGroups; i++ {
		nodeStrategies = append(nodeStrategies, testutils.CountToStrategy{
			Count:    numNodes / numGroups,
			Strategy: testutils.NewLabelNodePrepareStrategy(nodeAffinityKey, fmt.Sprintf("%v", i)),
		})
	}
	return nodeStrategies
}

func (nodeAffinity *NodeAffinity) mutatePod(numPods int, podList []*v1.Pod) {
	numGroups := nodeAffinity.numGroups
	nodeAffinityKey := nodeAffinity.nodeAffinityKey
	for i := 0; i < numGroups; i++ {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "sched-perf-node-affinity-pod-",
			},
			Spec: testutils.MakePodSpec(),
		}
		pod.Spec.Affinity = &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{
						{
							MatchExpressions: []v1.NodeSelectorRequirement{
								{
									Key:      nodeAffinityKey,
									Operator: nodeAffinity.Operator,
									Values:   []string{fmt.Sprintf("%v", i)},
								},
							},
						},
					},
				},
			},
		}
		podList = append(podList, pod)
	}
	return
}

// Interface that every predicate or priority structure should implement.
type UpdateNodePodConfig interface {
	// mutateNode mutates the node strategies
	mutateNode()
	// mutatePod mutates the pod configs
	mutatePod()
}

// High Level Configuration that every node should implement.
type PriorityConfiguration struct {
	nodeAffinity     NodeAffinity
	interpodAffinity InterpodAffinity
}

type InterpodAffinity struct {
	Enabled     bool
	Operator    metav1.LabelSelectorOperator
	affinityKey string
	Labels      map[string]string
	TopologyKey string
}

type NodeAffinity struct {
	Enabled         bool   //If not enabled, node affinity is disabled.
	numGroups       int    // the % of nodes and pods that should match. Higher # -> smaller performance deficit at scale.
	nodeAffinityKey string // the number of labels needed to match.  Higher # -> larger performance deficit at scale.
	Operator        v1.NodeSelectorOperator
}

// TODO: As of now, returning configs hardcoded, need to read from yaml or some other file. A lot to validate as well.
func readInPriorityConfiguration() *PriorityConfiguration {
	return &PriorityConfiguration{
		nodeAffinity: NodeAffinity{
			Enabled:         true,
			numGroups:       10,
			nodeAffinityKey: "kubernetes.io/sched-perf-node-affinity",
			Operator:        v1.NodeSelectorOpIn,
		},

		interpodAffinity: InterpodAffinity{
			Enabled:     false,
			Operator:    metav1.LabelSelectorOpIn,
			affinityKey: "security",
			Labels:      map[string]string{"security": "S1"},
			TopologyKey: "region",
		},
	}
}

func (pc *PriorityConfiguration) mutate(config *testConfig) {
	nodeAffinity := pc.nodeAffinity
	podCreatorConfig := testutils.NewTestPodCreatorConfig()
	var nodeStrategies []testutils.CountToStrategy
	var podList []*v1.Pod
	// It seems this should be the last one to run as this
	if nodeAffinity.Enabled {
		// Mutate Node
		nodeStrategies = nodeAffinity.mutateNode(config.numNodes)
		// Mutate Pod
		nodeAffinity.mutatePod(config.numPods, podList)
		for _, pod := range podList {
			podCreatorConfig.AddStrategy("sched-perf-node-affinity", config.numPods/nodeAffinity.numGroups,
				testutils.NewCustomCreatePodStrategy(pod),
			)
		}
		config.nodePreparer = framework.NewIntegrationTestNodePreparer(
			config.schedulerSupportFunctions.GetClient(),
			nodeStrategies, "scheduler-perf-")
		config.podCreator = testutils.NewTestPodCreator(config.schedulerSupportFunctions.GetClient(), podCreatorConfig)
	}
	return
}

func TestMain(m *testing.M) {
	// TODO: Read yaml file which has information on nodes, pods etc.
	// TODO: Validate the yaml file and convert it into datastructure that we have.
	/*flag.String("test.predicate", "", "Use -test.predicate")
	flag.String("test.priorities", "", "use -test.priorities")
	predicatesWithComma := flag.CommandLine.Lookup("test.predicate")
	prioritiesWithComma := flag.CommandLine.Lookup("test.priorities")
	predicates := strings.Split(predicatesWithComma.Value.String(), ",")
	priorities := strings.Split(prioritiesWithComma.Value.String(), ",")
	*/
	fmt.Println("a")
	flag.IntVar(&nodes, "test.nodes", 0, "use -test.nodes")
	fmt.Println("a a")

	flag.IntVar(&pods, "test.pods", 0, "use -test.pods")
	fmt.Println("sss a a")

	flag.Parse()
	fmt.Println("aa a a a")

	config := baseConfig()
	fmt.Println("a aa a a a")

	config.numNodes = nodes
	fmt.Println("a a aa a a a")

	config.numPods = pods
	fmt.Println("a a a a aa a a")

	// Fill in priority Configuration
	priorityConfig := readInPriorityConfiguration()
	fmt.Println("a a a a a a aaaa a")

	priorityConfig.mutate(config)

	fmt.Println("a a a a a a a a aaaaa")
	schedulePods(config)
}
