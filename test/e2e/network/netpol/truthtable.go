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
	"github.com/pkg/errors"
	"strings"
)

// TruthTable takes in n items and maintains an n x n table of booleans for each ordered pair
type TruthTable struct {
	Items   []string
	itemSet map[string]bool
	Values  map[string]map[string]bool
}

// NewTruthTable creates a new truth table
func NewTruthTable(items []string, defaultValue *bool) *TruthTable {
	itemSet := map[string]bool{}
	values := map[string]map[string]bool{}
	for _, from := range items {
		itemSet[from] = true
		values[from] = map[string]bool{}
		if defaultValue != nil {
			for _, to := range items {
				values[from][to] = *defaultValue
			}
		}
	}
	return &TruthTable{
		Items:   items,
		itemSet: itemSet,
		Values:  values,
	}
}

// IsComplete returns true if there's a value set for every single pair of items, otherwise it returns false.
func (tt *TruthTable) IsComplete() bool {
	for _, from := range tt.Items {
		for _, to := range tt.Items {
			if _, ok := tt.Values[from][to]; !ok {
				return false
			}
		}
	}
	return true
}

// Set sets the value for from->to
func (tt *TruthTable) Set(from string, to string, value bool) {
	dict, ok := tt.Values[from]
	if !ok {
		panic(errors.Errorf("key %s not found in map", from))
	}
	if _, ok := tt.itemSet[to]; !ok {
		panic(errors.Errorf("key %s not allowed", to))
	}
	dict[to] = value
}

// SetAllFrom sets all values where from = 'from'
func (tt *TruthTable) SetAllFrom(from string, value bool) {
	dict, ok := tt.Values[from]
	if !ok {
		panic(errors.Errorf("key %s not found in map", from))
	}
	for _, to := range tt.Items {
		dict[to] = value
	}
}

// SetAllTo sets all values where to = 'to'
func (tt *TruthTable) SetAllTo(to string, value bool) {
	if _, ok := tt.itemSet[to]; !ok {
		panic(errors.Errorf("key %s not found", to))
	}
	for _, from := range tt.Items {
		tt.Values[from][to] = value
	}
}

// Get gets the specified value
func (tt *TruthTable) Get(from string, to string) bool {
	dict, ok := tt.Values[from]
	if !ok {
		panic(errors.Errorf("key %s not found in map", from))
	}
	val, ok := dict[to]
	if !ok {
		panic(errors.Errorf("key %s not found in map (%+v)", to, dict))
	}
	return val
}

// Compare is used to check two truth tables for equality, returning its
// result in the form of a third truth table.  Both tables are expected to
// have identical items.
func (tt *TruthTable) Compare(other *TruthTable) *TruthTable {
	values := map[string]map[string]bool{}
	for from, dict := range tt.Values {
		values[from] = map[string]bool{}
		for to, val := range dict {
			values[from][to] = val == other.Values[from][to]
		}
	}
	return &TruthTable{
		Items:   tt.Items,
		itemSet: tt.itemSet,
		Values:  values,
	}
}

// PrettyPrint produces a nice visual representation.
func (tt *TruthTable) PrettyPrint(indent string) string {
	header := indent + strings.Join(append([]string{"-"}, tt.Items...), "\t")
	lines := []string{header}
	for _, from := range tt.Items {
		line := []string{from}
		for _, to := range tt.Items {
			val := "X"
			if tt.Values[from][to] {
				val = "."
			}
			line = append(line, val)
		}
		lines = append(lines, indent+strings.Join(line, "\t"))
	}
	return strings.Join(lines, "\n")
}
