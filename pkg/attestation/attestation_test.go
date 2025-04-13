/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"encoding/json"
	"testing"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/vex"
)

func TestSerialize(t *testing.T) {
	att := New()
	pred := vex.New()
	pred.Author = "Chainguard"
	att.Predicate = pred

	var b bytes.Buffer
	err := att.ToJSON(&b)
	require.NoError(t, err)

	att2 := New()
	err = json.Unmarshal(b.Bytes(), &att2)
	require.NoError(t, err)
	require.Equal(t, att2.Predicate.Author, "Chainguard")
}

func TestAddSubjects(t *testing.T) {
	att := New()

	// Test adding valid subjects
	validSubs := []intoto.Subject{
		{
			Name:   "test1",
			Digest: map[string]string{"sha256": "abc123"},
		},
		{
			Name:   "test2",
			Digest: map[string]string{"sha256": "def456"},
		},
	}
	err := att.AddSubjects(validSubs)
	require.NoError(t, err)
	require.Len(t, att.Subject, 2)
	require.Equal(t, validSubs[0], att.Subject[0])
	require.Equal(t, validSubs[1], att.Subject[1])

	// Test adding subject with no digest
	invalidSubs := []intoto.Subject{
		{
			Name: "test3",
		},
	}
	err = att.AddSubjects(invalidSubs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "subject test3 has no digests")
	require.Len(t, att.Subject, 2) // Length should not change
}
