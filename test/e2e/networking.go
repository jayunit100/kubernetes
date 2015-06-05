/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package e2e

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	//"sync"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Networking", func() {
	f := NewFramework("nettest")

	BeforeEach(func() {
		//Assert basic external connectivity.
		//Since this is not really a test of kubernetes in any way, we
		//leave it as a pre-test assertion, rather than a Ginko test.
		By("Executing a successful http request from the external internet")
		resp, err := http.Get("http://google.com")
		if err != nil {
			Failf("Unable to connect/talk to the internet: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			Failf("Unexpected error code, expected 200, got, %v (%v)", resp.StatusCode, resp)
		}
	})

	// First test because it has no dependencies on variables created later on.
	It("should provide unchanging, static URL paths for kubernetes api services.", func() {
		tests := []struct {
			path string
		}{
			{path: "/validate"},
			{path: "/healthz"},
			// TODO: test proxy links here
		}
		for _, test := range tests {
			By(fmt.Sprintf("testing: %s", test.path))
			data, err := f.Client.RESTClient.Get().
				Namespace(f.Namespace.Name).
				AbsPath(test.path).
				DoRaw()
			if err != nil {
				Failf("Failed: %v\nBody: %s", err, string(data))
			}
		}
	})

	//1 service and 120 seconds is the original networking.go test,
	//which confirms that all hosts can eventually ping each other over
	//their service endpoint on 8080.
	services := [...]int{1}       //, 5}
	timeouts := [...]float64{120} //, 160}

	for ii := range services {
		It(
			fmt.Sprintf("should support intrapod communication between all hosts in %v parallel services", services[ii]),
			func(doneTimeout Done) {
				RunNetTest(doneTimeout, f, Makeports(services[ii]), "1.4")
			},
			timeouts[ii])
	}
})

//PeerStatus will either fail, pass, or continue polling
func PollPeerStatus(ch chan int, f *Framework, svc *api.Service) bool {

	Logf("Polling !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!          ")
	getDetails := func() ([]byte, error) {
		return f.Client.Get().
			Namespace(f.Namespace.Name).
			Prefix("proxy").
			Resource("services").
			Name(svc.Name).
			Suffix("read").
			DoRaw()
	}

	getStatus := func() ([]byte, error) {
		return f.Client.Get().
			Namespace(f.Namespace.Name).
			Prefix("proxy").
			Resource("services").
			Name(svc.Name).
			Suffix("status").
			DoRaw()
	}

	passed := false
	//Try for 60 times, where we poll every few seconds.
	for i := 0; !passed && i < 60; i++ {
		time.Sleep(2 * time.Second)
		Logf("About to make a proxy status call")
		start := time.Now()
		body, err := getStatus()
		Logf("Proxy status call returned in %v", time.Since(start))
		if err != nil {
			Logf("Attempt %v: service/pod still starting. (error: '%v')", i, err)
			continue
		}
		// Finally, we pass/fail the test based on if the container's response body, as to wether or not it was able to find peers.
		switch {
		case string(body) == "pass":
			Logf("Passed on attempt %v. Cleaning up.", i)
			passed = true
		case string(body) == "running":
			Logf("Attempt %v: test still running", i)
		case string(body) == "fail":
			if body, err = getDetails(); err != nil {
				Failf("Failed on attempt %v. Cleaning up. Error reading details: %v", i, err)
			} else {
				Failf("Failed on attempt %v. Cleaning up. Details:\n%s", i, string(body))
			}
		case strings.Contains(string(body), "no endpoints available"):
			Logf("Attempt %v: waiting on service/endpoints", i)
		default:
			Logf("Unexpected response:\n%s", body)
		}
	}

	if !passed {
		if body, err := getDetails(); err != nil {
			Failf("Timed out. Cleaning up. Error reading details: %v", err)
		} else {
			Failf("Timed out. Cleaning up. Details:\n%s", string(body))
		}
	}
	Logf("sending final result to channel")
	ch <- -1
	Logf("RETURN")
	return passed
}

//RunNetTest Creates a single pod on each host which serves
//on a unique port in the cluster.  It then binds a service to
//that port, so that there are "n" nodes to balance traffic to -
//finally, each node reaches out to ping every other node in
//the cluster on the given port.
//The more ports you give, the more services will be spun up,
//i.e. one service per port.
//To test basic pod networking, send a single port.
//To soak test the services, we can send a range (i.e. 8000-9000).
func RunNetTest(doneTimeout Done, f *Framework, ports []int, nettestVersion string) {
	defer GinkgoRecover()
	defer close(doneTimeout)

	//res := make([]float, 5)
	sem := make(chan int, len(ports))
	for ii := range ports {
		//required to copy the var when we're creating it.
		i := ports[ii]

		go func() {
			defer GinkgoRecover()

			//    defer GinkgoRecover()
			var svcname = fmt.Sprintf("nettest-%v", i)
			//defer close(done)
			if testContext.Provider == "vagrant" {
				//By("Skipping test which is broken for vagrant (See https://github.com/GoogleCloudPlatform/kubernetes/issues/3580)")
				return
			}

			//By(fmt.Sprintf("Creating a service named %q in namespace %q", svcname, f.Namespace.Name))
			svc, err := f.Client.Services(f.Namespace.Name).Create(&api.Service{
				ObjectMeta: api.ObjectMeta{
					Name: svcname,
					Labels: map[string]string{
						"name": svcname,
					},
				},
				Spec: api.ServiceSpec{
					Ports: []api.ServicePort{{
						Protocol:   "TCP",
						Port:       i,
						TargetPort: util.NewIntOrStringFromInt(i),
					}},
					Selector: map[string]string{
						"name": svcname,
					},
				},
			})
			if err != nil {
				Failf("unable to create test service named [%s] %v", svc.Name, err)
			} else {
				Logf("CREATED SERVICE............")
			}

			//By("Creating a webserver (pending) pod on each node")

			nodes, err := f.Client.Nodes().List(labels.Everything(), fields.Everything())
			if err != nil {
				Failf("Failed to list nodes: %v", err)
			}

			Logf("launching pod per node.....")
			podNames := LaunchNetTestPodPerNode(i, nettestVersion, f, nodes, svcname)
			Logf("*(*********************** Launched test pods for %v", i)
			//By("Waiting for the webserver pods to transition to Running state")

			for _, podName := range podNames {
				err = f.WaitForPodRunning(podName)
				Expect(err).NotTo(HaveOccurred())
				By(fmt.Sprintf("Waiting for connectivity to be verified [ port =  %v ] ", i))
				//once response OK, evaluate response body for pass/fail.
				PollPeerStatus(sem, f, svc)

			}

			Logf("*(************************ Finished test pods for %v", i)
		}()
	}
	//Expect(string(body)).To(Equal("pass"))
	//now wait for the all X nettests to complete...
	//By("Waiting for all connectivities to be verified")
	for ii := range ports {
		Logf("Now waiting on port %v", ports[ii])
		<-sem
		Logf("finished ! port %v", ports[ii])
	}
	Logf("------------- all done, returning --------------")
	return
}

//Makeports makes a bunch of ports from 8080->8080+n
func Makeports(n int) []int {
	m := make([]int, n)
	for i := 0; i < n; i++ {
		m[i] = 8080 + i
	}
	return m
}

//Return a function which runs a single net-test.  This function can be
//called in many threads for load testing
func LaunchNetTestPodPerNode(port int, version string, f *Framework, nodes *api.NodeList, name string) []string {
	podNames := []string{}

	totalPods := len(nodes.Items)

	Expect(totalPods).NotTo(Equal(0))

	for _, node := range nodes.Items {
		pod, err := f.Client.Pods(f.Namespace.Name).Create(&api.Pod{
			ObjectMeta: api.ObjectMeta{
				GenerateName: name + "-",
				Labels: map[string]string{
					"name": name,
				},
			},
			Spec: api.PodSpec{
				Containers: []api.Container{
					{
						Name: "webserver",
						//versions ~ 1.3 (original RO service) or 1.4 (new service token tests)
						Image: "gcr.io/google_containers/nettest:" + version,
						Args: []string{
							"-port=" + strconv.Itoa(port),
							"-service=" + name,
							//peers >= totalPods should be asserted by the container.
							//the nettest container finds peers by looking up list of svc endpoints.
							fmt.Sprintf("-peers=%d", totalPods),
							"-namespace=" + f.Namespace.Name},
						Ports: []api.ContainerPort{{ContainerPort: port}},
					},
				},
				NodeName:      node.Name,
				RestartPolicy: api.RestartPolicyNever,
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Logf("Created pod %s on node %s", pod.ObjectMeta.Name, node.Name)
		podNames = append(podNames, pod.ObjectMeta.Name)
	}
	return podNames
}
