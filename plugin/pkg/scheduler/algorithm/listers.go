/*
Copyright 2014 The Kubernetes Authors.

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

package algorithm

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/v1"
	extensions "k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
)

// PredicateStore is an interface taken from the kubernetes client, for the sake of decoupling.
type PredicateStore interface {
	Add(obj interface{}) error
	Update(obj interface{}) error
	Delete(obj interface{}) error
	List() []interface{}
	ListKeys() []string
	Get(obj interface{}) (item interface{}, exists bool, err error)
	GetByKey(key string) (item interface{}, exists bool, err error)

	// Replace will delete the contents of the store, using instead the
	// given list. Store takes ownership of the list, you should not reference
	// it after calling this function.
	Replace([]interface{}, string) error
	Resync() error
}

// PredicateIndexer is an interface taken from the kubernetes client.
type PredicateIndexer interface {
	PredicateStore
	// Retrieve list of objects that match on the named indexing function
	Index(indexName string, obj interface{}) ([]interface{}, error)
	// ListIndexFuncValues returns the list of generated values of an Index func
	ListIndexFuncValues(indexName string) []string
	// ByIndex lists object that match on the named indexing function with the exact key
	ByIndex(indexName, indexKey string) ([]interface{}, error)
	// GetIndexer return the indexers
	GetIndexers() map[string]func(obj interface{}) ([]string, error)

	// AddIndexers adds more indexers to this store.  If you call this after you already have data
	// in the store, the results are undefined.
	AddIndexers(newIndexers Indexers) error
}

// PredicatePersistentVolumeClaimInfo has methods to work with PersistentVolumeClaim resources.
type PredicatePersistentVolumeClaimInfo interface {
	Create(*api.PersistentVolumeClaim) (*api.PersistentVolumeClaim, error)
	Update(*api.PersistentVolumeClaim) (*api.PersistentVolumeClaim, error)
	UpdateStatus(*api.PersistentVolumeClaim) (*api.PersistentVolumeClaim, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	//	Get(name string, options v1.GetOptions) (*api.PersistentVolumeClaim, error)
	List(opts v1.ListOptions) (*api.PersistentVolumeClaimList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *api.PersistentVolumeClaim, err error)
	// PersistentVolumeClaimExpansion
}

type PersistentVolumeClaimsGetter interface {
	PersistentVolumeClaims(namespace string) PredicatePersistentVolumeClaimInfo
}

// NodeLister interface represents anything that can list nodes for a scheduler.
type NodeLister interface {
	// We explicitly return []*v1.Node, instead of v1.NodeList, to avoid
	// performing expensive copies that are unneded.
	List() ([]*v1.Node, error)
}

// FakeNodeLister implements NodeLister on a []string for test purposes.
type FakeNodeLister []*v1.Node

// List returns nodes as a []string.
func (f FakeNodeLister) List() ([]*v1.Node, error) {
	return f, nil
}

// PodLister interface represents anything that can list pods for a scheduler.
type PodLister interface {
	// We explicitly return []*v1.Pod, instead of v1.PodList, to avoid
	// performing expensive copies that are unneded.
	List(labels.Selector) ([]*v1.Pod, error)
}

// FakePodLister implements PodLister on an []v1.Pods for test purposes.
type FakePodLister []*v1.Pod

// List returns []*v1.Pod matching a query.
func (f FakePodLister) List(s labels.Selector) (selected []*v1.Pod, err error) {
	for _, pod := range f {
		if s.Matches(labels.Set(pod.Labels)) {
			selected = append(selected, pod)
		}
	}
	return selected, nil
}

// ServiceLister interface represents anything that can produce a list of services; the list is consumed by a scheduler.
type ServiceLister interface {
	// Lists all the services
	List(labels.Selector) ([]*v1.Service, error)
	// Gets the services for the given pod
	GetPodServices(*v1.Pod) ([]*v1.Service, error)
}

// FakeServiceLister implements ServiceLister on []v1.Service for test purposes.
type FakeServiceLister []*v1.Service

// List returns v1.ServiceList, the list of all services.
func (f FakeServiceLister) List(labels.Selector) ([]*v1.Service, error) {
	return f, nil
}

// GetPodServices gets the services that have the selector that match the labels on the given pod.
func (f FakeServiceLister) GetPodServices(pod *v1.Pod) (services []*v1.Service, err error) {
	var selector labels.Selector

	for i := range f {
		service := f[i]
		// consider only services that are in the same namespace as the pod
		if service.Namespace != pod.Namespace {
			continue
		}
		selector = labels.Set(service.Spec.Selector).AsSelectorPreValidated()
		if selector.Matches(labels.Set(pod.Labels)) {
			services = append(services, service)
		}
	}
	return
}

// ControllerLister interface represents anything that can produce a list of ReplicationController; the list is consumed by a scheduler.
type ControllerLister interface {
	// Lists all the replication controllers
	List(labels.Selector) ([]*v1.ReplicationController, error)
	// Gets the services for the given pod
	GetPodControllers(*v1.Pod) ([]*v1.ReplicationController, error)
}

// EmptyControllerLister implements ControllerLister on []v1.ReplicationController returning empty data
type EmptyControllerLister struct{}

// List returns nil
func (f EmptyControllerLister) List(labels.Selector) ([]*v1.ReplicationController, error) {
	return nil, nil
}

// GetPodControllers returns nil
func (f EmptyControllerLister) GetPodControllers(pod *v1.Pod) (controllers []*v1.ReplicationController, err error) {
	return nil, nil
}

// FakeControllerLister implements ControllerLister on []v1.ReplicationController for test purposes.
type FakeControllerLister []*v1.ReplicationController

// List returns []v1.ReplicationController, the list of all ReplicationControllers.
func (f FakeControllerLister) List(labels.Selector) ([]*v1.ReplicationController, error) {
	return f, nil
}

// GetPodControllers gets the ReplicationControllers that have the selector that match the labels on the given pod
func (f FakeControllerLister) GetPodControllers(pod *v1.Pod) (controllers []*v1.ReplicationController, err error) {
	var selector labels.Selector

	for i := range f {
		controller := f[i]
		if controller.Namespace != pod.Namespace {
			continue
		}
		selector = labels.Set(controller.Spec.Selector).AsSelectorPreValidated()
		if selector.Matches(labels.Set(pod.Labels)) {
			controllers = append(controllers, controller)
		}
	}
	if len(controllers) == 0 {
		err = fmt.Errorf("Could not find Replication Controller for pod %s in namespace %s with labels: %v", pod.Name, pod.Namespace, pod.Labels)
	}

	return
}

// ReplicaSetLister interface represents anything that can produce a list of ReplicaSet; the list is consumed by a scheduler.
type ReplicaSetLister interface {
	// Gets the replicasets for the given pod
	GetPodReplicaSets(*v1.Pod) ([]*extensions.ReplicaSet, error)
}

// EmptyReplicaSetLister implements ReplicaSetLister on []extensions.ReplicaSet returning empty data
type EmptyReplicaSetLister struct{}

// GetPodReplicaSets returns nil
func (f EmptyReplicaSetLister) GetPodReplicaSets(pod *v1.Pod) (rss []*extensions.ReplicaSet, err error) {
	return nil, nil
}

// FakeReplicaSetLister implements ControllerLister on []extensions.ReplicaSet for test purposes.
type FakeReplicaSetLister []*extensions.ReplicaSet

// GetPodReplicaSets gets the ReplicaSets that have the selector that match the labels on the given pod
func (f FakeReplicaSetLister) GetPodReplicaSets(pod *v1.Pod) (rss []*extensions.ReplicaSet, err error) {
	var selector labels.Selector

	for _, rs := range f {
		if rs.Namespace != pod.Namespace {
			continue
		}
		selector, err = metav1.LabelSelectorAsSelector(rs.Spec.Selector)
		if err != nil {
			return
		}

		if selector.Matches(labels.Set(pod.Labels)) {
			rss = append(rss, rs)
		}
	}
	if len(rss) == 0 {
		err = fmt.Errorf("Could not find ReplicaSet for pod %s in namespace %s with labels: %v", pod.Name, pod.Namespace, pod.Labels)
	}

	return
}
