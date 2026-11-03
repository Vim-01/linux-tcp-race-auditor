package main

import (
	"reflect"
	"testing"
)

// TestParseSweepList covers the success paths of parseSweepList.
// Error paths call fatalf (os.Exit), so they are exercised via the
// CLI, not here.
func TestParseSweepList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []int
	}{
		{"empty", "", nil},
		{"simple", "0,15,30,45,60", []int{0, 15, 30, 45, 60}},
		{"negatives", "-20,-10,0,10,20", []int{-20, -10, 0, 10, 20}},
		{"single", "30", []int{30}},
		{"spaces", " 0 , 15 ,30 ", []int{0, 15, 30}},
		{"empty-segments", "0,,15,", []int{0, 15}},
	}
	for _, tc := range cases {
		got := parseSweepList("-sweep", tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: parseSweepList(%q) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}
