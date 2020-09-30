package utils

import (
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"strings"
)

// PodString represents a namespace 'x' + pod 'a' as "x/a".
type PodString string

// NewPodString instantiates a PodString from the given namespace and name.
func NewPodString(namespace string, podName string) PodString {
	return PodString(fmt.Sprintf("%s/%s", namespace, podName))
}

// String converts back to a string
func (pod PodString) String() string {
	return string(pod)
}

func (pod PodString) split() (string, string) {
	pieces := strings.Split(string(pod), "/")
	if len(pieces) != 2 {
		panic(errors.New(fmt.Sprintf("expected ns/pod, found %+v", pieces)))
	}
	return pieces[0], pieces[1]
}

// Namespace extracts the namespace
func (pod PodString) Namespace() string {
	ns, _ := pod.split()
	return ns
}

// PodName extracts the pod name
func (pod PodString) PodName() string {
	_, podName := pod.split()
	return podName
}

// Peer is used for matching pods by either or both of the pod's namespace and name.
type Peer struct {
	Namespace string
	Pod       string
}

// Matches checks whether the Peer matches the PodString:
// - an empty namespace means the namespace will always match
// - otherwise, the namespace must match the PodString's namespace
// - same goes for Pod: empty matches everything, otherwise must match exactly
func (p *Peer) Matches(pod PodString) bool {
	return (p.Namespace == "" || p.Namespace == pod.Namespace()) && (p.Pod == "" || p.Pod == pod.PodName())
}

type Reachability struct {
	Expected *TruthTable
	Observed *TruthTable
	Pods     []PodString
}

// NewReachability instantiates a reachability
func NewReachability(pods []PodString, defaultExpectation bool) *Reachability {
	items := []string{}
	for _, pod := range pods {
		items = append(items, string(pod))
	}
	r := &Reachability{
		Expected: NewTruthTable(items, &defaultExpectation),
		Observed: NewTruthTable(items, nil),
		Pods:     pods,
	}
	return r
}

// AllowLoopback is a convenience func to access Expected and re-enabl
// all loopback to true.  in general call it after doing other logical
// stuff in loops since loopback logic follows no policy.
func (r *Reachability) AllowLoopback() {
	for _, item := range r.Expected.Items {
		r.Expected.Set(item, item, true)
	}
}

// Expect sets the expected value for a single observation
func (r *Reachability) Expect(from PodString, to PodString, isConnected bool) {
	r.Expected.Set(string(from), string(to), isConnected)
}

// ExpectAllIngress defines that any traffic going into the pod will be allowed/denied (true/false)
func (r *Reachability) ExpectAllIngress(pod PodString, connected bool) {
	r.Expected.SetAllTo(string(pod), connected)
	if !connected {
		log.Infof("Blacklisting all traffic *to* %s", pod)
	}
}

// ExpectAllEgress defines that any traffic going out of the pod will be allowed/denied (true/false)
func (r *Reachability) ExpectAllEgress(pod PodString, connected bool) {
	r.Expected.SetAllFrom(string(pod), connected)
	if !connected {
		log.Infof("Blacklisting all traffic *from* %s", pod)
	}
}

// ExpectPeer sets expected values using Peer matchers
func (r *Reachability) ExpectPeer(from *Peer, to *Peer, connected bool) {
	for _, fromPod := range r.Pods {
		if from.Matches(fromPod) {
			for _, toPod := range r.Pods {
				if to.Matches(toPod) {
					r.Expected.Set(string(fromPod), string(toPod), connected)
				}
			}
		}
	}
}

// Observe records a single connectivity observation
func (r *Reachability) Observe(pod1 PodString, pod2 PodString, isConnected bool) {
	r.Observed.Set(string(pod1), string(pod2), isConnected)
}

// Summary produces a useful summary of expected and observed data
func (r *Reachability) Summary() (trueObs int, falseObs int, comparison *TruthTable) {
	comparison = r.Expected.Compare(r.Observed)
	if !comparison.IsComplete() {
		panic("observations not complete!")
	}
	falseObs = 0
	trueObs = 0
	for _, dict := range comparison.Values {
		for _, val := range dict {
			if val {
				trueObs++
			} else {
				falseObs++
			}
		}
	}
	return trueObs, falseObs, comparison
}

// PrintSummary prints the summary
func (r *Reachability) PrintSummary(printExpected bool, printObserved bool, printComparison bool) {
	right, wrong, comparison := r.Summary()
	fmt.Printf("reachability: correct:%v, incorrect:%v, result=%t\n\n", right, wrong, wrong == 0)
	if printExpected {
		fmt.Printf("expected:\n\n%s\n\n\n", r.Expected.PrettyPrint(""))
	}
	if printObserved {
		fmt.Printf("observed:\n\n%s\n\n\n", r.Observed.PrettyPrint(""))
	}
	if printComparison {
		fmt.Printf("comparison:\n\n%s\n\n\n", comparison.PrettyPrint(""))
	}
}
