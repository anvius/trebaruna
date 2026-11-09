package domain_test

import (
	"fmt"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/desktop/domain"
)

func placed(tree []domain.PlacedSignature) string {
	text := ""
	for _, node := range tree {
		text += fmt.Sprintf("%d:%d ", node.Index, node.Depth)
	}
	return text
}

// TestACounterSignatureHangsUnderWhatItSigns, at any depth, in order.
func TestACounterSignatureHangsUnderWhatItSigns(t *testing.T) {
	tree := domain.SignatureTree([]domain.SignatureNode{
		{Field: "1"}, {Field: "2"}, {Field: "1.1", Countersigns: "1"}, {Field: "1.1.1", Countersigns: "1.1"}, {Field: "2.1", Countersigns: "2"},
	})
	if got := placed(tree); got != "0:0 2:1 3:2 1:0 4:1 " {
		t.Errorf("tree %s", got)
	}
}

// TestNothingIsLost: a missing parent or a loop puts a signature at the top.
func TestNothingIsLost(t *testing.T) {
	tree := domain.SignatureTree([]domain.SignatureNode{
		{Field: "a", Countersigns: "b"}, {Field: "b", Countersigns: "a"}, {Field: "c", Countersigns: "gone"}, {Field: "c"},
	})
	if len(tree) != 4 {
		t.Fatalf("%d of 4 signatures placed: %s", len(tree), placed(tree))
	}
	seen := map[int]bool{}
	for _, node := range tree {
		if seen[node.Index] {
			t.Errorf("signature %d placed twice", node.Index)
		}
		seen[node.Index] = true
	}
}
