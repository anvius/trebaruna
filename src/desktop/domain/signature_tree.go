package domain

// SignatureNode is a signature as a verification lists it: its name, and
// the name of the signature it counter-signs, if any.
type SignatureNode struct {
	Field        string
	Countersigns string
}

// PlacedSignature is where a signature stands in the tree: its position in
// the verification and how deep it hangs.
type PlacedSignature struct {
	Index int
	Depth int
}

// SignatureTree orders signatures as a tree: each counter-signature right
// under the signature it signs, in the order the verification gives them. A
// counter-signature whose signature is not listed, or a loop, stands at the
// top rather than vanishing.
func SignatureTree(nodes []SignatureNode) []PlacedSignature {
	byField := map[string]int{}
	for index, node := range nodes {
		if _, seen := byField[node.Field]; !seen && node.Field != "" {
			byField[node.Field] = index
		}
	}
	children := map[int][]int{}
	var roots []int
	for index, node := range nodes {
		parent, listed := byField[node.Countersigns]
		if node.Countersigns == "" || !listed || parent == index {
			roots = append(roots, index)
			continue
		}
		children[parent] = append(children[parent], index)
	}

	placed := make([]PlacedSignature, 0, len(nodes))
	visited := map[int]bool{}
	var visit func(index, depth int)
	visit = func(index, depth int) {
		if visited[index] {
			return
		}
		visited[index] = true
		placed = append(placed, PlacedSignature{Index: index, Depth: depth})
		for _, child := range children[index] {
			visit(child, depth+1)
		}
	}
	for _, root := range roots {
		visit(root, 0)
	}
	for index := range nodes {
		visit(index, 0)
	}
	return placed
}
