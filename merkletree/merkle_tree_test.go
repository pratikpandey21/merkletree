package merkletree

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBasicConstruction verifies the tree is built correctly
func TestBasicConstruction(t *testing.T) {
	tests := []struct {
		name    string
		data    [][]byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    [][]byte{},
			wantErr: true,
		},
		{
			name: "single leaf",
			data: [][]byte{[]byte("hello")},
		},
		{
			name: "two leaves",
			data: [][]byte{[]byte("hello"), []byte("world")},
		},
		{
			name: "odd number of leaves",
			data: [][]byte{[]byte("a"), []byte("b"), []byte("c")},
		},
		{
			name: "power of two leaves",
			data: [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := NewMerkleTree(tt.data)

			if tt.wantErr {
				assert.Error(t, err, "expected error for empty data")
				return
			}

			require.NoError(t, err, "unexpected error creating tree")
			assert.NotNil(t, tree.Root, "root should not be nil")
			assert.Len(t, tree.Leaves, len(tt.data), "incorrect number of leaves")

			// Verify leaf data matches input
			for i, leaf := range tree.Leaves {
				assert.Equal(t, tt.data[i], leaf.Data, "leaf %d data mismatch", i)
			}
		})
	}
}

// TestRootHashDeterministic verifies same data produces same root
func TestRootHashDeterministic(t *testing.T) {
	data := [][]byte{
		[]byte("transaction1"),
		[]byte("transaction2"),
		[]byte("transaction3"),
		[]byte("transaction4"),
	}

	// Build tree multiple times
	var roots [][]byte
	for i := 0; i < 5; i++ {
		tree, err := NewMerkleTree(data)
		require.NoError(t, err, "failed to create tree")
		roots = append(roots, tree.Root.Hash)
	}

	// All roots should be identical
	for i := 1; i < len(roots); i++ {
		assert.Equal(t, roots[0], roots[i],
			"root hash not deterministic: iteration %d differs", i)
	}
}

// TestKnownRootHash verifies against a known correct root hash
func TestKnownRootHash(t *testing.T) {
	// Test vector with known result
	data := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
	}

	tree, err := NewMerkleTree(data)
	require.NoError(t, err, "failed to create tree")

	// Calculate expected root manually
	hashA := sha256.Sum256([]byte("a"))
	hashB := sha256.Sum256([]byte("b"))
	hashC := sha256.Sum256([]byte("c"))
	hashD := sha256.Sum256([]byte("d"))

	hashAB := sha256.Sum256(append(hashA[:], hashB[:]...))
	hashCD := sha256.Sum256(append(hashC[:], hashD[:]...))

	expectedRoot := sha256.Sum256(append(hashAB[:], hashCD[:]...))

	assert.Equal(t, expectedRoot[:], tree.Root.Hash,
		"incorrect root hash")
}

// TestProofGeneration verifies we can generate valid proofs
func TestProofGeneration(t *testing.T) {
	data := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
	}

	tree, err := NewMerkleTree(data)
	require.NoError(t, err, "failed to create tree")

	// Test proof for each leaf
	for i := range data {
		proof, err := tree.GenerateProof(i)
		assert.NoError(t, err, "failed to generate proof for index %d", i)

		// Verify proof has correct length
		expectedLen := 2 // log2(4) = 2
		assert.Len(t, proof, expectedLen,
			"incorrect proof length for index %d", i)
	}

	// Test out of bounds
	_, err = tree.GenerateProof(-1)
	assert.Error(t, err, "expected error for negative index")

	_, err = tree.GenerateProof(len(data))
	assert.Error(t, err, "expected error for out of bounds index")
}

// TestProofVerification tests if proofs actually verify correctly
func TestProofVerification(t *testing.T) {
	data := [][]byte{
		[]byte("alice"),
		[]byte("bob"),
		[]byte("charlie"),
		[]byte("david"),
	}

	tree, err := NewMerkleTree(data)
	require.NoError(t, err, "failed to create tree")

	// Our naive verification is broken
	t.Run("naive_verification_broken", func(t *testing.T) {
		for i, item := range data {
			proof, err := tree.GenerateProof(i)
			require.NoError(t, err, "failed to generate proof")

			// This assertion will fail, proving our implementation is broken
			assert.True(t, VerifyProof(item, proof, tree.Root.Hash),
				"verification failed for index %d - implementation is broken!", i)
		}
	})
}

// TestProofNonMembership verifies that wrong data fails verification
func TestProofNonMembership(t *testing.T) {
	data := [][]byte{
		[]byte("alice"),
		[]byte("bob"),
		[]byte("charlie"),
		[]byte("david"),
	}

	tree, err := NewMerkleTree(data)
	require.NoError(t, err, "failed to create tree")

	// Generate proof for "alice"
	proof, err := tree.GenerateProof(0)
	require.NoError(t, err, "failed to generate proof")

	// Try to verify with different data - should fail
	wrongData := []byte("eve")
	assert.False(t, VerifyProof(wrongData, proof, tree.Root.Hash),
		"verification succeeded for wrong data")

	// Try to verify with wrong root - should fail
	wrongRoot := sha256.Sum256([]byte("wrong"))
	assert.False(t, VerifyProof(data[0], proof, wrongRoot[:]),
		"verification succeeded with wrong root")
}

// TestTreeProperties validates essential Merkle tree properties
func TestTreeProperties(t *testing.T) {
	data := [][]byte{
		[]byte("1"), []byte("2"), []byte("3"), []byte("4"),
		[]byte("5"), []byte("6"), []byte("7"), []byte("8"),
	}

	tree, err := NewMerkleTree(data)
	require.NoError(t, err, "failed to create tree")

	t.Run("all_leaves_have_data", func(t *testing.T) {
		for i, leaf := range tree.Leaves {
			assert.NotNil(t, leaf.Data, "leaf %d has nil data", i)
			assert.Equal(t, data[i], leaf.Data, "leaf %d data mismatch", i)
		}
	})

	t.Run("internal_nodes_have_no_data", func(t *testing.T) {
		var checkNode func(*Node, bool)
		checkNode = func(node *Node, isLeaf bool) {
			if node == nil {
				return
			}

			if !isLeaf && node.Data != nil {
				assert.Fail(t, "internal node has data - should be nil")
			}

			if node.Left != nil || node.Right != nil {
				checkNode(node.Left, false)
				checkNode(node.Right, false)
			}
		}

		isRootLeaf := len(tree.Leaves) == 1
		checkNode(tree.Root, isRootLeaf)
	})

	t.Run("hash_consistency", func(t *testing.T) {
		var verifyHashes func(*Node) error
		verifyHashes = func(node *Node) error {
			if node == nil || (node.Left == nil && node.Right == nil) {
				return nil
			}

			combinedHash := append(node.Left.Hash, node.Right.Hash...)
			expectedHash := sha256.Sum256(combinedHash)

			if !assert.Equal(t, expectedHash[:], node.Hash) {
				return fmt.Errorf("hash mismatch at node")
			}

			if err := verifyHashes(node.Left); err != nil {
				return err
			}
			return verifyHashes(node.Right)
		}

		err := verifyHashes(tree.Root)
		assert.NoError(t, err, "hash verification failed")
	})
}

// TestDataIntegrity verifies that changing data changes the root
func TestDataIntegrity(t *testing.T) {
	data := [][]byte{
		[]byte("transfer $100 to Alice"),
		[]byte("transfer $200 to Bob"),
		[]byte("transfer $300 to Charlie"),
	}

	tree1, err := NewMerkleTree(data)
	require.NoError(t, err)

	// Modify one transaction
	data[1] = []byte("transfer $2000 to Bob")

	tree2, err := NewMerkleTree(data)
	require.NoError(t, err)

	assert.NotEqual(t, tree1.Root.Hash, tree2.Root.Hash,
		"root hash didn't change when data was modified")

	// Even a tiny change should affect the root
	data[1] = []byte("transfer $200 to Bob.")

	tree3, err := NewMerkleTree(data)
	require.NoError(t, err)

	assert.NotEqual(t, tree1.Root.Hash, tree3.Root.Hash,
		"root hash didn't change for small data modification")
}

// TestComprehensiveVerification proves our implementation is fundamentally broken
func TestComprehensiveVerification(t *testing.T) {
	data := [][]byte{
		[]byte("A"),
		[]byte("B"),
		[]byte("C"),
		[]byte("D"),
	}

	tree, err := NewMerkleTree(data)
	require.NoError(t, err, "failed to create tree")

	// Manually calculate expected tree
	hashA := sha256.Sum256([]byte("A"))
	hashB := sha256.Sum256([]byte("B"))
	hashC := sha256.Sum256([]byte("C"))
	hashD := sha256.Sum256([]byte("D"))

	hashAB := sha256.Sum256(append(hashA[:], hashB[:]...))
	hashCD := sha256.Sum256(append(hashC[:], hashD[:]...))

	expectedRoot := sha256.Sum256(append(hashAB[:], hashCD[:]...))

	// Verify the root matches
	assert.Equal(t, expectedRoot[:], tree.Root.Hash, "root hash mismatch")

	// Test each proof - these will fail with our broken implementation
	testCases := []struct {
		index    int
		data     []byte
		expected bool
		name     string
	}{
		{0, []byte("A"), true, "valid proof for A"},
		{1, []byte("B"), true, "valid proof for B"},
		{2, []byte("C"), true, "valid proof for C"},
		{3, []byte("D"), true, "valid proof for D"},
		{0, []byte("X"), false, "invalid data with valid index"},
		{1, []byte("A"), false, "wrong data for index"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := tree.GenerateProof(tc.index)
			require.NoError(t, err, "failed to generate proof")

			result := VerifyProof(tc.data, proof, tree.Root.Hash)
			assert.Equal(t, tc.expected, result,
				"verification result mismatch for %s", tc.name)
		})
	}
}

func generateRandomData(count int, size int) [][]byte {
	data := make([][]byte, count)
	for i := 0; i < count; i++ {
		data[i] = make([]byte, size)
		rand.Read(data[i])
	}
	return data
}

func BenchmarkNaiveMerkleTree(b *testing.B) {
	testCases := []struct {
		name      string
		dataCount int
	}{
		{"100_leaves", 100},
		{"1000_leaves", 1000},
		{"10000_leaves", 10000},
		{"100000_leaves", 100000},
	}

	for _, tc := range testCases {
		b.Run(tc.name+"_build", func(b *testing.B) {
			data := generateRandomData(tc.dataCount, 32)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = NewMerkleTree(data)
			}
		})

		b.Run(tc.name+"_proof", func(b *testing.B) {
			data := generateRandomData(tc.dataCount, 32)
			tree, _ := NewMerkleTree(data)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = tree.GenerateProof(tc.dataCount / 2)
			}
		})
	}
}

// Memory usage test
func TestMemoryUsage(t *testing.T) {
	var m runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&m)
	allocBefore := m.Alloc

	data := generateRandomData(100000, 32)
	tree, _ := NewMerkleTree(data)

	runtime.GC()
	runtime.ReadMemStats(&m)
	allocAfter := m.Alloc

	fmt.Printf("Memory used for 100k leaves: %d MB\n", (allocAfter-allocBefore)/1024/1024)
	fmt.Printf("Root hash: %x\n", tree.Root.Hash)
}
