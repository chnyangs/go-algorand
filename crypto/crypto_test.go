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
	"crypto/sha256"
	"math/rand"
	"testing"

	"github.com/algorand/go-algorand/protocol"
)

type TestingHashable struct {
	data []byte
}

func (s TestingHashable) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.TestHashable, s.data
}

func randString() (b TestingHashable) {
	d := make([]byte, 20)
	_, err := rand.Read(d)
	if err != nil {
		panic(err)
	}
	return TestingHashable{d}
}

func signVerify(t *testing.T, c *SignatureSecrets, c2 *SignatureSecrets) {
	s := randString()
	sig := c.Sign(s)
	if !c.Verify(s, sig, true) {
		t.Errorf("correct signature failed to verify (plain)")
	}

	s2 := randString()
	sig2 := c.Sign(s2)
	if c.Verify(s, sig2, true) {
		t.Errorf("wrong message incorrectly verified (plain)")
	}

	sig3 := c2.Sign(s)
	if c.Verify(s, sig3, true) {
		t.Errorf("wrong key incorrectly verified (plain)")
	}

	if c.Verify(s2, sig3, true) {
		t.Errorf("wrong message+key incorrectly verified (plain)")
	}
}

func proveVerifyVrf(t *testing.T, c *VRFSecrets, c2 *VRFSecrets) {
	d1 := randString()
	var leavesHashArr [1024]*[sha256.Size]byte
	for i, leave := range Leaves {
		// Check two leaves have same parents
		leaveHash32 := [32]byte{}
		copy(leaveHash32[:], leave)
		leavesHashArr[i] = &leaveHash32
	}
	i := 1021
	j := 10
	mu, _ := GenRandomBytes(32)
	d1 = TestingHashable{mu}
	pf, ok := c2.SK.Prove(d1, leavesHashArr[:], int32(i), int32(j))
	if !ok {
		t.Errorf("failed to construct proof (corrupt vrf secrets?)")
	}
	if ok, _ := c2.PK.Verify(d1, leavesHashArr[:], int32(i), int32(j), pf); !ok {
		t.Errorf("correct proof failed to verify (proof)")
	}
	//d2 := randString()
	//mu2, _ := GenRandomBytes(32)
	//d2 = TestingHashable{mu2}
	//i2 := 985
	//j2 := 2
	//pf3, ok := c2.SK.Prove(d2, leavesHashArr[:], int32(i2), int32(j2))
	//if !ok {
	//	t.Errorf("failed to construct proof (corrupt vrf secrets?)")
	//}
	//if ok, _ := c2.PK.Verify(d2, leavesHashArr[:], int32(i2), int32(j2), pf3); ok {
	//	t.Errorf("wrong key incorrectly verified (proof)")
	//}
	//if ok, _ := c2.PK.Verify(d1, leavesHashArr[:], int32(i), int32(j), pf); ok {
	//	t.Errorf("wrong message incorrectly verified (proof)")
	//}
}

func BenchmarkHash(b *testing.B) {
	s := randString()
	d := Hash(s.data)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		d = Hash(d[:])
	}
	_ = d
}
