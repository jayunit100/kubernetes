package utils

import (
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type ProbeJob struct {
	PodFrom  PodString
	PodTo    PodString
	FromPort int
	ToPort   int
	Protocol v1.Protocol
}

type ProbeJobResults struct {
	Job         *ProbeJob
	IsConnected bool
	Err         error
	Command     string
}

func Validate(k8s *Kubernetes, reachability *Reachability, fromPort, toPort int, protocol v1.Protocol) {
	k8s.ClearCache()
	numberOfWorkers := 30
	allPods := GetAllPods()
	size := len(allPods) * len(allPods)
	jobs := make(chan *ProbeJob, size)
	results := make(chan *ProbeJobResults, size)
	for i := 0; i < numberOfWorkers; i++ {
		go probeWorker(k8s, jobs, results)
	}
	// TODO: find better metrics, this is only for POC.
	for _, podFrom := range allPods {
		for _, podTo := range allPods {
			jobs <- &ProbeJob{
				PodFrom:  podFrom,
				PodTo:    podTo,
				FromPort: fromPort,
				ToPort:   toPort,
				Protocol: protocol,
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
				log.Infof("Whitelisted pod connection was BLOCKED --- run '%v'", result.Command)
			} else {
				log.Infof("Blacklisted pod connection was ALLOWED --- run '%v'", result.Command)
			}
		}
	}
}

func probeWorker(k8s *Kubernetes, jobs <-chan *ProbeJob, results chan<- *ProbeJobResults) {
	for job := range jobs {
		podFrom := job.PodFrom
		podTo := job.PodTo
		connected, err, command := k8s.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), job.Protocol, job.FromPort, job.ToPort)
		results <- &ProbeJobResults{
			Job:         job,
			IsConnected: connected,
			Err:         err,
			Command:     command,
		}
	}
}
