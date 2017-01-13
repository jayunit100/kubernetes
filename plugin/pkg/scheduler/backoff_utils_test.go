package scheduler

import (
	"k8s.io/kubernetes/pkg/types"
	"testing"
	"time"
)

type fakeClock struct {
	t time.Time
}

func (f *fakeClock) Now() time.Time {
	return f.t
}

func TestBackoff(t *testing.T) {
	clock := fakeClock{}
	backoff := CreatePodBackoff(1*time.Second, 60*time.Second)

	tests := []struct {
		podID            types.NamespacedName
		expectedDuration time.Duration
		advanceClock     time.Duration
	}{
		{
			podID:            types.NamespacedName{Namespace: "default", Name: "foo"},
			expectedDuration: 1 * time.Second,
		},
		{
			podID:            types.NamespacedName{Namespace: "default", Name: "foo"},
			expectedDuration: 2 * time.Second,
		},
		{
			podID:            types.NamespacedName{Namespace: "default", Name: "foo"},
			expectedDuration: 4 * time.Second,
		},
		{
			podID:            types.NamespacedName{Namespace: "default", Name: "bar"},
			expectedDuration: 1 * time.Second,
			advanceClock:     120 * time.Second,
		},
		// 'foo' should have been gc'd here.
		{
			podID:            types.NamespacedName{Namespace: "default", Name: "foo"},
			expectedDuration: 1 * time.Second,
		},
	}

	for _, test := range tests {
		duration := backoff.GetEntry(test.podID).getBackoff(backoff.maxDuration)
		if duration != test.expectedDuration {
			t.Errorf("expected: %s, got %s for %s", test.expectedDuration.String(), duration.String(), test.podID)
		}
		clock.t = clock.t.Add(test.advanceClock)
		backoff.Gc()
	}
	fooID := types.NamespacedName{Namespace: "default", Name: "foo"}
	backoff.perPodBackoff[fooID].backoff = 60 * time.Second
	duration := backoff.GetEntry(fooID).getBackoff(backoff.maxDuration)
	if duration != 60*time.Second {
		t.Errorf("expected: 60, got %s", duration.String())
	}
	// Verify that we split on namespaces correctly, same name, different namespace
	fooID.Namespace = "other"
	duration = backoff.GetEntry(fooID).getBackoff(backoff.maxDuration)
	if duration != 1*time.Second {
		t.Errorf("expected: 1, got %s", duration.String())
	}
}
