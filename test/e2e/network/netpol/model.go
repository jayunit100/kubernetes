/*
Copyright 2020 The Kubernetes Authors.

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

package netpol

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

// Model defines the namespaces, deployments, services, pods, containers and associated
// data for network policy test cases and provides the source of truth
type Model struct {
	Namespaces    []*Namespace
	allPodStrings *[]PodString
	allPods       *[]*Pod
	// the raw data
	NamespaceNames []string
	PodNames       []string
	Ports          []int32
	Protocols      []v1.Protocol
	//lint:ignore U1000 this variable is used in probe.go
	DNSDomain string
}

// NewModel instantiates a model
func NewModel(namespaces []string, podNames []string, ports []int32, protocols []v1.Protocol, dnsDomain string) *Model {
	model := &Model{
		NamespaceNames: namespaces,
		PodNames:       podNames,
		Ports:          ports,
		Protocols:      protocols,
		DNSDomain:      dnsDomain,
	}
	framework.Logf("DNSDomain %v", model.DNSDomain)

	for _, ns := range namespaces {
		var pods []*Pod
		for _, podName := range podNames {
			var containers []*Container
			for _, port := range ports {
				for _, protocol := range protocols {
					containers = append(containers, &Container{
						Port:     port,
						Protocol: protocol,
					})
				}
			}
			pods = append(pods, &Pod{
				Namespace:  ns,
				Name:       podName,
				Containers: containers,
			})
		}
		model.Namespaces = append(model.Namespaces, &Namespace{Name: ns, Pods: pods})
	}
	return model
}

// NewReachability instantiates a default-true reachability from the model's pods
func (m *Model) NewReachability() *Reachability {
	return NewReachability(m.AllPods(), true)
}

// AllPodStrings returns a slice of all pod strings
func (m *Model) AllPodStrings() []PodString {
	if m.allPodStrings == nil {
		var pods []PodString
		for _, ns := range m.Namespaces {
			for _, pod := range ns.Pods {
				pods = append(pods, pod.PodString())
			}
		}
		m.allPodStrings = &pods
	}
	return *m.allPodStrings
}

// AllPods returns a slice of all pods
func (m *Model) AllPods() []*Pod {
	if m.allPods == nil {
		var pods []*Pod
		for _, ns := range m.Namespaces {
			for _, pod := range ns.Pods {
				pods = append(pods, pod)
			}
		}
		m.allPods = &pods
	}
	return *m.allPods
}

// FindPod returns the pod of matching namespace and name, or an error
func (m *Model) FindPod(ns string, name string) (*Pod, error) {
	for _, namespace := range m.Namespaces {
		for _, pod := range namespace.Pods {
			if namespace.Name == ns && pod.Name == name {
				return pod, nil
			}
		}
	}
	return nil, errors.Errorf("unable to find pod %s/%s", ns, name)
}

// Namespace is the abstract representation of what matters to network policy
// tests for a namespace; i.e. it ignores kube implementation details
type Namespace struct {
	Name string
	Pods []*Pod
}

// Spec builds a kubernetes namespace spec
func (ns *Namespace) Spec() *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ns.Name,
			Labels: ns.LabelSelector(),
		},
	}
}

// LabelSelector returns the default labels that should be placed on a namespace
// in order for it to be uniquely selectable by label selectors
func (ns *Namespace) LabelSelector() map[string]string {
	return map[string]string{"ns": ns.Name}
}

// Pod is the abstract representation of what matters to network policy tests for
// a pod; i.e. it ignores kube implementation details
type Pod struct {
	Namespace  string
	Name       string
	Containers []*Container
}

// FindContainer returns the container matching port and protocol; otherwise, an error
func (p *Pod) FindContainer(port int32, protocol v1.Protocol) (*Container, error) {
	for _, cont := range p.Containers {
		if cont.Port == port && cont.Protocol == protocol {
			return cont, nil
		}
	}
	return nil, errors.Errorf("unable to find container in pod %s/%s, port %d, protocol %s", p.Namespace, p.Name, port, protocol)
}

// PodString returns a corresponding pod string
func (p *Pod) PodString() PodString {
	return NewPodString(p.Namespace, p.Name)
}

// ContainerSpecs builds kubernetes container specs for the pod
func (p *Pod) ContainerSpecs() []v1.Container {
	var containers []v1.Container
	for _, cont := range p.Containers {
		containers = append(containers, cont.Spec())
	}
	return containers
}

func (p *Pod) labelSelectorKey() string {
	return "pod"
}

func (p *Pod) labelSelectorValue() string {
	return p.Name
}

// LabelSelector returns the default labels that should be placed on a pod/deployment
// in order for it to be uniquely selectable by label selectors
func (p *Pod) LabelSelector() map[string]string {
	return map[string]string{
		p.labelSelectorKey(): p.labelSelectorValue(),
	}
}

// KubePod returns the kube pod
func (p *Pod) KubePod() *v1.Pod {
	zero := int64(0)
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.Name,
			Labels:    p.LabelSelector(),
			Namespace: p.Namespace,
		},
		Spec: v1.PodSpec{
			TerminationGracePeriodSeconds: &zero,
			Containers:                    p.ContainerSpecs(),
		},
	}
}

// QualifiedServiceAddress returns the address that can be used to hit a service from
// any namespace in the cluster
func (p *Pod) QualifiedServiceAddress(dnsDomain string) string {
	return fmt.Sprintf("%s.%s.svc.%s", p.ServiceName(), p.Namespace, dnsDomain)
}

// ServiceName returns the unqualified service name
func (p *Pod) ServiceName() string {
	return fmt.Sprintf("s-%s-%s", p.Namespace, p.Name)
}

// Service returns a kube service spec
func (p *Pod) Service() *v1.Service {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.ServiceName(),
			Namespace: p.Namespace,
		},
		Spec: v1.ServiceSpec{
			Selector: p.LabelSelector(),
		},
	}
	for _, container := range p.Containers {
		service.Spec.Ports = append(service.Spec.Ports, v1.ServicePort{
			Name:     fmt.Sprintf("service-port-%s-%d", strings.ToLower(string(container.Protocol)), container.Port),
			Protocol: container.Protocol,
			Port:     container.Port,
		})
	}
	return service
}

// Container is the abstract representation of what matters to network policy tests for
// a container; i.e. it ignores kube implementation details
type Container struct {
	Port     int32
	Protocol v1.Protocol
}

// Name returns the container name
func (c *Container) Name() string {
	return fmt.Sprintf("cont-%d-%s", c.Port, strings.ToLower(string(c.Protocol)))
}

// PortName returns the container port name
func (c *Container) PortName() string {
	return fmt.Sprintf("serve-%d-%s", c.Port, strings.ToLower(string(c.Protocol)))
}

// Spec returns the kube container spec
func (c *Container) Spec() v1.Container {
	var (
		// agnHostImage is the image URI of AgnHost
		agnHostImage = imageutils.GetE2EImage(imageutils.Agnhost)
		cmd          []string
	)

	switch c.Protocol {
	case v1.ProtocolTCP:
		cmd = []string{"/agnhost", "serve-hostname", "--tcp", "--http=false", "--port", fmt.Sprintf("%d", c.Port)}
	case v1.ProtocolUDP:
		cmd = []string{"/agnhost", "serve-hostname", "--udp", "--http=false", "--port", fmt.Sprintf("%d", c.Port)}
	case v1.ProtocolSCTP:
		cmd = []string{"/agnhost", "netexec", "--sctp-port", fmt.Sprintf("%d", c.Port)}
	default:
		framework.Failf("invalid protocol %v", c.Protocol)
	}
	return v1.Container{
		Name:            c.Name(),
		ImagePullPolicy: v1.PullIfNotPresent,
		Image:           agnHostImage,
		Command:         cmd,
		SecurityContext: &v1.SecurityContext{},
		Ports: []v1.ContainerPort{
			{
				ContainerPort: c.Port,
				Name:          c.PortName(),
				Protocol:      c.Protocol,
			},
		},
	}
}
