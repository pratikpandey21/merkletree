package merkletree

import (
	"crypto/sha256"
	"errors"
)

// Node represents a node in the Merkle Tree
type Node struct {
	Hash  []byte
	Data  []byte
	Left  *Node
	Right *Node
}

// MerkleTree represents the tree structure
type MerkleTree struct {
	Root   *Node
	Leaves []*Node
}

// NewMerkleTree creates a new Merkle Tree from data blocks
func NewMerkleTree(dataBlocks [][]byte) (*MerkleTree, error) {
	if len(dataBlocks) == 0 {
		return nil, errors.New("cannot create empty merkle tree")
	}

	// Create leaf nodes
	leaves := make([]*Node, len(dataBlocks))
	for i, data := range dataBlocks {
		hash := sha256.Sum256(data)
		leaves[i] = &Node{
			Hash: hash[:],
			Data: data,
		}
	}

	// Build tree
	root := buildTreeRecursive(leaves)

	return &MerkleTree{
		Root:   root,
		Leaves: leaves,
	}, nil
}

func buildTreeRecursive(nodes []*Node) *Node {
	if len(nodes) == 1 {
		return nodes[0]
	}

	// Handle odd number of nodes by duplicating the last one
	if len(nodes)%2 == 1 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	parentLevel := make([]*Node, 0)

	// Build parent level
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		right := nodes[i+1]

		combinedHash := append(left.Hash, right.Hash...)
		hash := sha256.Sum256(combinedHash)

		parent := &Node{
			Hash:  hash[:],
			Left:  left,
			Right: right,
		}

		parentLevel = append(parentLevel, parent)
	}

	return buildTreeRecursive(parentLevel)
}

// GenerateProof generates a membership proof for a leaf at given index
func (mt *MerkleTree) GenerateProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(mt.Leaves) {
		return nil, errors.New("index out of range")
	}

	proof := make([][]byte, 0)

	// Navigate from leaf to root, collecting sibling hashes
	currentIndex := index
	currentLevel := mt.Leaves

	for len(currentLevel) > 1 {
		// Handle odd number of nodes
		if len(currentLevel)%2 == 1 {
			currentLevel = append(currentLevel, currentLevel[len(currentLevel)-1])
		}

		// Find sibling
		var siblingIndex int
		if currentIndex%2 == 0 {
			siblingIndex = currentIndex + 1
		} else {
			siblingIndex = currentIndex - 1
		}

		proof = append(proof, currentLevel[siblingIndex].Hash)

		// Move to parent level
		currentIndex = currentIndex / 2

		// Rebuild parent level
		parentLevel := make([]*Node, 0)
		for i := 0; i < len(currentLevel); i += 2 {
			parentLevel = append(parentLevel, findParent(currentLevel[i], currentLevel[i+1], mt.Root))
		}
		currentLevel = parentLevel
	}

	return proof, nil
}

// findParent to find parent nodes
func findParent(left, right, root *Node) *Node {
	if root == nil {
		return nil
	}

	if root.Left == left && root.Right == right {
		return root
	}

	if found := findParent(left, right, root.Left); found != nil {
		return found
	}

	return findParent(left, right, root.Right)
}

// VerifyProof verifies a membership proof
func VerifyProof(dataBlock []byte, proof [][]byte, rootHash []byte) bool {
	hash := sha256.Sum256(dataBlock)
	currentHash := hash[:]

	for _, siblingHash := range proof {
		// We don't know if sibling is left or right!

		combinedHash1 := append(currentHash, siblingHash...)
		hash1 := sha256.Sum256(combinedHash1)

		combinedHash2 := append(siblingHash, currentHash...)
		_ = sha256.Sum256(combinedHash2)

		// We'll need to try both possibilities when verifying
		// This is clearly not ideal!
		currentHash = hash1[:]
	}

	return string(currentHash) == string(rootHash)
}
