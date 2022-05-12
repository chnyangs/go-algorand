// Copyright (C) 2019-2022 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"

	"github.com/algorand/go-algorand/protocol"
)

// Hashable is an interface implemented by an object that can be represented
// with a sequence of bytes to be hashed or signed, together with a type ID
// to distinguish different types of objects.
type Hashable interface {
	ToBeHashed() (protocol.HashID, []byte)
}

// HashRep appends the correct hashid before the message to be hashed.
func HashRep(h Hashable) []byte {
	hashid, data := h.ToBeHashed()
	return append([]byte(hashid), data...)
}

// DigestSize is the number of bytes in the preferred hash Digest used here.
const DigestSize = sha512.Size256

// Digest represents a 32-byte value holding the 256-bit Hash digest.
type Digest [DigestSize]byte

// ToSlice converts Digest to slice, is used by bookkeeping.PaysetCommit
func (d Digest) ToSlice() []byte {
	return d[:]
}

// String returns the digest in a human-readable Base32 string
func (d Digest) String() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(d[:])
}

// TrimUint64 returns the top 64 bits of the digest and converts to uint64
func (d Digest) TrimUint64() uint64 {
	return binary.LittleEndian.Uint64(d[:8])
}

// IsZero return true if the digest contains only zeros, false otherwise
func (d Digest) IsZero() bool {
	return d == Digest{}
}

// DigestFromString converts a string to a Digest
func DigestFromString(str string) (d Digest, err error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(str)
	if err != nil {
		return d, err
	}
	if len(decoded) != len(d) {
		msg := fmt.Sprintf(`Attempted to decode a string which was not a Digest: "%v"`, str)
		return d, errors.New(msg)
	}
	copy(d[:], decoded[:])
	return d, err
}

// Hash computes the SHASum512_256 hash of an array of bytes
func Hash(data []byte) Digest {
	return sha512.Sum512_256(data)
}
func CalculateHash(msg []byte) []byte {
	h := sha256.New()
	if _, err := h.Write(msg); err != nil {
		return nil
	}
	return h.Sum(nil)
}

// HashObj computes a hash of a Hashable object and its type
func HashObj(h Hashable) Digest {
	return Hash(HashRep(h))
}

// NewHash returns a sha512-256 object to do the same operation as Hash()
func NewHash() hash.Hash {
	return sha512.New512_256()
}

func ComputeMerkleRoot(leaveHashes [][]byte, intermediateHashes map[int][][]byte) [32]byte {
	numOfLeaves := len(leaveHashes)
	//log.Println("Num of Leaves:", numOfLeaves)
	index := 0
	levelLen := numOfLeaves / 2
	treeHeight := math.Log(float64(numOfLeaves)) / math.Log(2)
	//log.Println("treeHeight", treeHeight)
	var tempLeavesHashArr = make([][]byte, levelLen)
	for i, _ := range leaveHashes {
		if index < numOfLeaves {
			intermediateHash := sha256.Sum256(append(leaveHashes[index][:], leaveHashes[index+1][:]...))
			//log.Println(i, index, index+1, numOfLeaves, intermediateHash, hex.EncodeToString(intermediateHash[:]))
			tempLeavesHashArr[i] = intermediateHash[:]
			if numOfLeaves == 2 {
				intermediateHashes[int(treeHeight)] = tempLeavesHashArr
				//log.Println("*****", treeHeight, intermediateHashes)
				return intermediateHash
			}
			index += 2
		} else {
			//log.Println("Completed Round", i)
			break
		}
	}
	if treeHeight == 10 {
		intermediateHashes[int(treeHeight)] = leaveHashes
	} else {
		intermediateHashes[int(treeHeight)] = tempLeavesHashArr
	}
	return ComputeMerkleRoot(tempLeavesHashArr, intermediateHashes)
}

// AuthPath is used to house intermediate information needed to generate a Branch.
type AuthPath struct {
	numLeaves   uint32
	matchedBits []byte
	bits        []byte
	allHashes   []*[sha256.Size]byte
	finalHashes []*[sha256.Size]byte
}

// MerkleBranch holds intermediate state while validating a merkle path.
type MerkleBranch struct {
	numLeaves uint32
	bitsUsed  uint32
	hashUsed  uint32
	hashes    [][sha256.Size]byte
	inHashes  [][sha256.Size]byte
	bits      []byte
}

// calcTreeWidth calculates the width of the tree at a given height.
// calcTreeWidth calculates and returns the the number of nodes (width) or a
// merkle tree at the given depth-first height.
func calcTreeWidth(num, height uint32) uint32 {
	return (num + (1 << height) - 1) >> height
}
func GenRandomBytes(size int) (blk []byte, err error) {
	blk = make([]byte, size)
	_, err = rand.Read(blk)
	return
}
func ConcatDigests(hashes ...*[sha256.Size]byte) *[sha256.Size]byte {
	h := sha256.New()
	for _, hash := range hashes {
		h.Write(hash[:])
	}
	var rv [sha256.Size]byte
	copy(rv[:], h.Sum(nil))
	return &rv
}
func CalculateAuthPath(leaves []*[sha256.Size]byte, hash *[sha256.Size]byte) *Branch {
	numLeaves := uint32(len(leaves))
	if numLeaves == 0 {
		return nil
	}
	ap := AuthPath{
		numLeaves:   numLeaves,
		matchedBits: make([]byte, 0, numLeaves),
		allHashes:   leaves,
	}

	for _, v := range ap.allHashes {
		if v != nil && *v == *hash {
			ap.matchedBits = append(ap.matchedBits, 0x01)
		} else {
			ap.matchedBits = append(ap.matchedBits, 0x00)
		}
	}

	// Calculate the number of merkle branches (height) in the tree.
	height := uint32(0)
	for calcTreeWidth(ap.numLeaves, height) > 1 {
		height++
	}

	// Build the depth-first partial merkle tree.
	ap.traverseAndBuild(height, 0)

	// Create merkle branch.
	mb := &Branch{
		NumLeaves: numLeaves,
		Hashes:    make([][sha256.Size]byte, 0, len(ap.finalHashes)),
		Flags:     make([]byte, (len(ap.bits)+7)/8),
	}

	// Create bitmap.
	for i := uint32(0); i < uint32(len(ap.bits)); i++ {
		mb.Flags[i/8] |= ap.bits[i] << (i % 8)
	}

	// Copy hashes
	for _, hash := range ap.finalHashes {
		mb.Hashes = append(mb.Hashes, *hash)
	}

	return mb
}

// VerifyAuthPath takes a Branch and ensures that it is a valid tree.
func VerifyAuthPath(mb *Branch) (*[sha256.Size]byte, error) {
	if mb.NumLeaves == 0 || len(mb.Hashes) == 0 {
		return nil, errors.New("empty merkle branch")
	}

	m := &MerkleBranch{
		bits:      bytes2bits(mb.Flags),
		inHashes:  mb.Hashes,
		numLeaves: mb.NumLeaves,
	}

	height := uint32(math.Ceil(math.Log2(float64(mb.NumLeaves))))
	merkleRoot, err := m.extract(height, 0)
	if err != nil {
		return nil, err
	}

	// Validate that we consumed all bits and bobs.
	flagByte := int(math.Floor(float64(m.bitsUsed / 8)))
	if flagByte+1 < len(mb.Flags) && mb.Flags[flagByte] > 1<<m.bitsUsed%8 {
		return nil, fmt.Errorf("did not consume all flag bits")
	}

	if m.hashUsed != uint32(len(mb.Hashes)) {
		return nil, fmt.Errorf("did not consume all hashes")
	}

	return merkleRoot, nil
}

// calcHash returns the hash for a sub-tree given a depth-first height and
// node position.
func (a *AuthPath) calcHash(height, pos uint32) *[sha256.Size]byte {
	if height == 0 {
		return a.allHashes[pos]
	}

	var right *[sha256.Size]byte
	left := a.calcHash(height-1, pos*2)
	if pos*2+1 < calcTreeWidth(a.numLeaves, height-1) {
		right = a.calcHash(height-1, pos*2+1)
	} else {
		right = left
	}
	return ConcatDigests(left, right)
}

// bytes2bits converts merkle tree bitmap into a byte array.
func bytes2bits(b []byte) []byte {
	bits := make([]byte, 0, len(b)*8)
	for i := 0; i < len(b); i++ {
		for j := uint(0); j < 8; j++ {
			bits = append(bits, (b[i]>>j)&0x01)
		}
	}

	return bits
}

// traverseAndBuild builds a partial merkle tree using a recursive depth-first
// approach.
func (a *AuthPath) traverseAndBuild(height, pos uint32) {
	// Determine whether this node is a parent of a matched node.
	var isParent byte
	for i := pos << height; i < (pos+1)<<height && i < a.numLeaves; i++ {
		isParent |= a.matchedBits[i]
	}
	a.bits = append(a.bits, isParent)

	// When the node is a leaf node or not a parent of a matched node,
	// append the hash to the list that will be part of the final merkle
	// block.
	if height == 0 || isParent == 0x00 {
		a.finalHashes = append(a.finalHashes, a.calcHash(height, pos))
		return
	}

	// Descend into the left child and process its sub-tree.
	a.traverseAndBuild(height-1, pos*2)

	// Descend into the right child and process its sub-tree if
	// there is one.
	if pos*2+1 < calcTreeWidth(a.numLeaves, height-1) {
		a.traverseAndBuild(height-1, pos*2+1)
	}
}

// extract recurse over the merkleBranch and returns the merkle root.
func (m *MerkleBranch) extract(height, pos uint32) (*[sha256.Size]byte, error) {
	parentOfMatch := m.bits[m.bitsUsed]
	m.bitsUsed++
	if height == 0 || parentOfMatch == 0 {
		hash := m.inHashes[m.hashUsed]
		m.hashUsed++
		if height == 0 && parentOfMatch == 1 {
			m.hashes = append(m.hashes, hash)
		}
		return &hash, nil
	}

	left, err := m.extract(height-1, pos*2)
	if err != nil {
		return nil, err
	}
	if pos*2+1 < calcTreeWidth(m.numLeaves, height-1) {
		right, err := m.extract(height-1, pos*2+1)
		if err != nil {
			return nil, err
		}
		if *left == *right {
			return nil, fmt.Errorf("equivalent hashes")
		}

		return ConcatDigests(left, right), nil
	}

	return ConcatDigests(left, left), nil
}
