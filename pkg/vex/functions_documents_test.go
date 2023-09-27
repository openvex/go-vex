/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeDocumentsWithOptions(t *testing.T) {
	doc1, err := Open("testdata/v001-1.vex.json")
	require.NoError(t, err)
	doc2, err := Open("testdata/v001-2.vex.json")
	require.NoError(t, err)

	doc3, err := Open("testdata/v020-1.vex.json")
	require.NoError(t, err)
	doc4, err := Open("testdata/v020-2.vex.json")
	require.NoError(t, err)

	for _, tc := range []struct {
		opts        *MergeOptions
		docs        []*VEX
		expectedDoc *VEX
		shouldErr   bool
	}{
		// Zero docs should fail
		{
			opts:        &MergeOptions{},
			docs:        []*VEX{},
			expectedDoc: &VEX{},
			shouldErr:   true,
		},
		// One doc results in the same doc
		{
			opts:        &MergeOptions{},
			docs:        []*VEX{doc1},
			expectedDoc: doc1,
			shouldErr:   false,
		},
		// Two docs, as they are
		{
			opts: &MergeOptions{},
			docs: []*VEX{doc1, doc2},
			expectedDoc: &VEX{
				Metadata: Metadata{},
				Statements: []Statement{
					doc1.Statements[0],
					doc2.Statements[0],
				},
			},
			shouldErr: false,
		},
		// Two docs, filter product
		{
			opts: &MergeOptions{
				Products: []string{"pkg:apk/wolfi/git@2.41.0-1"},
			},
			docs: []*VEX{doc3, doc4},
			expectedDoc: &VEX{
				Metadata: Metadata{},
				Statements: []Statement{
					doc4.Statements[0],
				},
			},
			shouldErr: false,
		},
		// Two docs, filter vulnerability
		{
			opts: &MergeOptions{
				Vulnerabilities: []string{"CVE-9876-54321"},
			},
			docs: []*VEX{doc3, doc4},
			expectedDoc: &VEX{
				Metadata: Metadata{},
				Statements: []Statement{
					doc3.Statements[0],
				},
			},
			shouldErr: false,
		},
	} {
		doc, err := MergeDocumentsWithOptions(tc.opts, tc.docs)
		if tc.shouldErr {
			require.Error(t, err)
			continue
		}

		// Check doc
		require.Len(t, doc.Statements, len(tc.expectedDoc.Statements))
		require.Equal(t, doc.Statements, tc.expectedDoc.Statements)
	}
}
