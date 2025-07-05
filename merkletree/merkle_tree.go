package merkletree

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Node represents a node in the Merkle Tree
type Node struct {
	Hash   []byte
	Data   []byte
	Left   *Node
	Right  *Node
	Parent *Node
	IsLeft bool
}

// ProofElement represents a single element in a Merkle proof with direction
type ProofElement struct {
	Hash   []byte
	IsLeft bool // true if this hash should be on the left during verification
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

	// Create parent level
	parentLevel := make([]*Node, 0, (len(nodes)+1)/2)

	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		var right *Node

		// Handle odd number of nodes by duplicating the last one
		if i+1 < len(nodes) {
			right = nodes[i+1]
		} else {
			// Create a copy of the last node for odd-sized levels
			right = &Node{
				Hash: make([]byte, len(left.Hash)),
				Data: nil, // Don't duplicate data, only hash
			}
			copy(right.Hash, left.Hash)
		}

		// Combine hashes (left || right)
		combinedHash := make([]byte, 0, len(left.Hash)+len(right.Hash))
		combinedHash = append(combinedHash, left.Hash...)
		combinedHash = append(combinedHash, right.Hash...)

		hash := sha256.Sum256(combinedHash)

		parent := &Node{
			Hash:  hash[:],
			Left:  left,
			Right: right,
		}

		// Set parent pointers and direction flags
		left.Parent = parent
		left.IsLeft = true
		right.Parent = parent
		right.IsLeft = false

		parentLevel = append(parentLevel, parent)
	}

	return buildTreeRecursive(parentLevel)
}

// GenerateProof generates a membership proof for a leaf at given index
func (mt *MerkleTree) GenerateProof(index int) ([]ProofElement, error) {
	if index < 0 || index >= len(mt.Leaves) {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, len(mt.Leaves))
	}

	proof := make([]ProofElement, 0)
	current := mt.Leaves[index]

	// Navigate from leaf to root using parent pointers - O(log n)
	for current.Parent != nil {
		parent := current.Parent
		var sibling *Node

		// Get sibling node
		if current.IsLeft {
			sibling = parent.Right
		} else {
			sibling = parent.Left
		}

		// Add sibling to proof with correct direction
		proof = append(proof, ProofElement{
			Hash:   sibling.Hash,
			IsLeft: !current.IsLeft, // Sibling's position relative to current
		})

		current = parent
	}

	return proof, nil
}

// VerifyProof verifies a membership proof
func VerifyProof(dataBlock []byte, proof []ProofElement, rootHash []byte) bool {
	if dataBlock == nil || rootHash == nil {
		return false
	}

	// Start with hash of the data block
	hash := sha256.Sum256(dataBlock)
	currentHash := hash[:]

	// Apply each proof element with correct ordering
	for _, element := range proof {
		var combinedHash []byte

		if element.IsLeft {
			// Sibling hash goes on the left
			combinedHash = make([]byte, 0, len(element.Hash)+len(currentHash))
			combinedHash = append(combinedHash, element.Hash...)
			combinedHash = append(combinedHash, currentHash...)
		} else {
			// Sibling hash goes on the right
			combinedHash = make([]byte, 0, len(currentHash)+len(element.Hash))
			combinedHash = append(combinedHash, currentHash...)
			combinedHash = append(combinedHash, element.Hash...)
		}

		hash := sha256.Sum256(combinedHash)
		currentHash = hash[:]
	}

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(currentHash, rootHash) == 1
}
