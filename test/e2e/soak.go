/*
Copyright 2015 Google Inc. All rights reserved.

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
	//"fmt"
	//"sync"
	//"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	//"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"
	//"github.com/GoogleCloudPlatform/kubernetes/pkg/util/wait"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func RunSVC(c *client.Client, name string, port int, containerport int, selector string) {

	var ns = api.NamespaceDefault
	//Can't declare svc, unless we plan to actually use it.
	_, err := c.Services(ns).Create(&api.Service{
		ObjectMeta: api.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"name": name,
			},
		},
		Spec: api.ServiceSpec{
			Port: 8080,
			Selector: map[string]string{
				"name": name,
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
}

// This test suite can take a long time to run, so by default it is disabled
// by being marked as Pending.  To enable this suite, remove the P from the
// front of PDescribe (PDescribe->Describe) and then all tests will
// be available
var _ = Describe("soaktest", func() {
	var c *client.Client
	var minionCount int
	rcname := [...]string{"frontend", "bpsLoadGenController", "redisslave"}
	services := [...]string{"frontend", "redisslave", "redis-master"}
	var ns string

	BeforeEach(func() {
		var err error
		c, err = loadClient()
		expectNoError(err)
		minions, err := c.Nodes().List()
		expectNoError(err)
		minionCount = len(minions.Items)
		Expect(minionCount).NotTo(BeZero())
		ns = api.NamespaceDefault
	})

	AfterEach(func() {
		// Remove any remaining pods from this test if the
		// replication controller still exists and the replica count
		// isn't 0.  This means the controller wasn't cleaned up
		// during the test so clean it up here
		for _, rc := range rcname {
			rcObj, err := c.ReplicationControllers(ns).Get(rc)
			if err == nil && rcObj.Spec.Replicas != 0 {
				DeleteRC(c, ns, rc)
			}
		}
		for _, svc := range services {
			c.Services(ns).Delete(svc)
		}
	})

	//It("should allow starting 100 pods per node", func() {
	//	RCName := "my-hostname-density100-" + string(util.NewUUID())
	//		RunRC(c, RCName, ns, "dockerfile/nginx", 100*minionCount)
	//})

	It("should have master components that can handle many short-lived pods", func() {
		name := "my-hostname-thrash-" + string(util.NewUUID())
		RunRC(c, name, ns, "kubernetes/pause", minionCount)
	})
})
