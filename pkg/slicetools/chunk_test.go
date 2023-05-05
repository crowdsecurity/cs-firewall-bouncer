package slicetools_test

import (
	"reflect"
	"testing"

	"github.com/crowdsecurity/cs-firewall-bouncer/pkg/slicetools"
)

func TestChunks(t *testing.T) {
	testCases := []struct {
		items     []int
		chunkSize int
		expected  [][]int
	}{
		{[]int{}, 2, [][]int{}},
		{[]int{1}, 2, [][]int{{1}}},
		{[]int{1, 2, 3, 4, 5}, 2, [][]int{{1, 2}, {3, 4}, {5}}},
		{[]int{1, 2, 3, 4, 5}, 3, [][]int{{1, 2, 3}, {4, 5}}},
		{[]int{1, 2, 3, 4, 5}, 5, [][]int{{1, 2, 3, 4, 5}}},
		{[]int{1, 2, 3, 4, 5}, 6, [][]int{{1, 2, 3, 4, 5}}},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			actual := slicetools.Chunks(tc.items, tc.chunkSize)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Expected %v, but got %v", tc.expected, actual)
			}
		})
	}
}
