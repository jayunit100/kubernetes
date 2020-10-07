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
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

// ProbeJob packages the data for the input of a pod->pod connectivity probe
type ProbeJob struct {
	PodFrom  PodString
	PodTo    PodString
	FromPort int
	ToPort   int
	Protocol v1.Protocol
}

// ProbeJobResults packages the data for the results of a pod->pod connectivity probe
type ProbeJobResults struct {
	Job         *ProbeJob
	IsConnected bool
	Err         error
	Command     string
}

// ProbePodToPodConnectivity runs a series of probes in kube, and records the results in `reachability`
func ProbePodToPodConnectivity(k8s *Kubernetes, reachability *Reachability, scenario *Scenario) {
	k8s.ClearCache()
	numberOfWorkers := 30
	allPods := GetAllPods()
	size := len(allPods) * len(allPods)
	jobs := make(chan *ProbeJob, size)
	results := make(chan *ProbeJobResults, size)
	for i := 0; i < numberOfWorkers; i++ {
		go probeWorker(k8s, jobs, results)
	}
	for _, podFrom := range allPods {
		for _, podTo := range allPods {
			jobs <- &ProbeJob{
				PodFrom:  podFrom,
				PodTo:    podTo,
				FromPort: scenario.FromPort,
				ToPort:   scenario.ToPort,
				Protocol: scenario.Protocol,
			}
		}
	}
	close(jobs)

	for i := 0; i < size; i++ {
		result := <-results
		job := result.Job
		if result.Err != nil {
			log.Infof("unable to perform probe %s -> %s: %v", job.PodFrom, job.PodTo, result.Err)
		}
		reachability.Observe(job.PodFrom, job.PodTo, result.IsConnected)
		expected := reachability.Expected.Get(job.PodFrom.String(), job.PodTo.String())
		if result.IsConnected != expected {
			log.Infof("Validation of %s -> %s FAILED !!!", job.PodFrom, job.PodTo)
			log.Infof("error %v ", result.Err)
			if expected {
				log.Infof("Expected allowed pod connection was instead BLOCKED --- run '%v'", result.Command)
			} else {
				log.Infof("Expected blocked pod connection was instead ALLOWED --- run '%v'", result.Command)
			}
		}
	}
}

func probeWorker(k8s *Kubernetes, jobs <-chan *ProbeJob, results chan<- *ProbeJobResults) {
	for job := range jobs {
		podFrom := job.PodFrom
		podTo := job.PodTo
		connected, command, err := k8s.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), job.Protocol, job.FromPort, job.ToPort)
		results <- &ProbeJobResults{
			Job:         job,
			IsConnected: connected,
			Err:         err,
			Command:     command,
		}
	}
}
