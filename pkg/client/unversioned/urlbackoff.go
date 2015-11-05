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

package unversioned

import
(
	"k8s.io/kubernetes/pkg/util/sets"
	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/util"
	"net/url"
	"time"
)

// Set of resp. Codes that we backoff for.
// In general these should be errors that indicate a server is overloaded.
// These shouldn't be configured by any user, we set them based on conventions
// described in

var serverIsOverloadedSet = sets.NewInt(429)
var maxResponseCode = 499

// URLBackoff struct implements the semantics on top of Backoff which
// we need for URL specific exponential backoff.
type URLBackoff struct {
	//Uses backoff as underlying implementation.
	Backoff *util.Backoff
}

// Clear clears the backoff data for all Urls.  This is useful for unit tests
// or other environments where we might want to start retrying at a fast rate.
func (b *URLBackoff) Reset() {
	b.Backoff = util.NewBackOff(1*time.Second, 120*time.Second)
}

// Disable makes the backoff trivial, i.e., sets it to zero.  This might be used
// by tests which want to run 1000s of mock requests without slowing down.
func (b *URLBackoff) Disable() {
	glog.V(4).Infof("Disabling backoff strategy")
	b.Backoff = util.NewBackOff(0*time.Second, 0*time.Second)
}

// Every url maps to a key, which is a subset of that url.
// For example, 127.0.0.1:8080/api/v2/abcde -> 127.0.0.1:8080.
func (b *URLBackoff) baseUrlKey(rawurl *url.URL) string {
	//Simple implementation for now, just the host.
	//We may backoff specific paths (i.e. "pods") differentially
	//in the future.
	host, err := url.Parse(rawurl.String())
	if err != nil {
		glog.V(4).Infof("Error extracting url: %v", rawurl)
		panic("bad url!")
	}
	return host.Host
}

// updateBackoff updates backoff metadata
func (b *URLBackoff) UpdateBackoff(actualUrl *url.URL, err error, responseCode int) {
	//range for retry counts that we store is [0,13]
	if responseCode > maxResponseCode || serverIsOverloadedSet.Has(responseCode) {
		b.Backoff.Next(b.baseUrlKey(actualUrl), time.Now())
		return
	} else if responseCode >= 300 || err != nil {
			glog.V(4).Infof("Client is returning errors: code %v, error %v", responseCode, err)
	}

	//If we got this far, there is no backoff required for this URL anymore.
	b.Backoff.Reset(b.baseUrlKey(actualUrl))
}

// calculateBackoff takes a url and back's off exponentially,
// based on its knowledge of existing failures.
func (b *URLBackoff) CalculateBackoff(actualUrl *url.URL) time.Duration {
	return b.Backoff.Get(b.baseUrlKey(actualUrl))
}
