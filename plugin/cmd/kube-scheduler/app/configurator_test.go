package app

import (
	"fmt"
	"testing"
)

func TestSchedulerConfigurator_Create(t *testing.T) {
	sc := &schedulerConfigurator{
		policyFile:        "missingfile",
		algorithmProvider: "algconfig",
	}

	_, error := sc.Create()

	fmt.Println(error)
}
