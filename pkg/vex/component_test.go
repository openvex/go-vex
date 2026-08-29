// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComponentMatches(t *testing.T) {
	for testCase, tc := range map[string]struct {
		identifier string
		component  *Component
		mustMatch  bool
	}{
		"iri": {
			"https://example.com/document.spdx.json#node",
			&Component{ID: "https://example.com/document.spdx.json#node"},
			true,
		},
		"misc identifier": {
			testMadeupIdentifier,
			&Component{
				Identifiers: map[IdentifierType]string{"customIdentifier": testMadeupIdentifier},
			},
			true,
		},
		"wrong misc identifier": {
			testMadeupIdentifier,
			&Component{
				Identifiers: map[IdentifierType]string{"customIdentifier": "another-string"},
			},
			false,
		},
		"same purl": {
			testWolfiCurlPURL,
			&Component{
				Identifiers: map[IdentifierType]string{PURL: testWolfiCurlPURL},
			},
			true,
		},
		"globing purl": {
			testOCICurlDigestPURL,
			&Component{
				Identifiers: map[IdentifierType]string{PURL: testOCICurlPURL},
			},
			true,
		},
		"globing purl (inverse)": {
			testOCICurlPURL,
			&Component{
				Identifiers: map[IdentifierType]string{
					PURL: testOCICurlDigestPURL,
				},
			},
			false,
		},
		"hash": {
			testSHA1Digest,
			&Component{
				Hashes: map[Algorithm]Hash{
					SHA1: testSHA1Digest,
				},
			},
			true,
		},
		"wrong hash": {
			testSHA1Digest,
			&Component{
				Hashes: map[Algorithm]Hash{
					SHA1: "b5cc41d90d7ccc195c4a24ceb32656942c9854ea",
				},
			},
			false,
		},
	} {
		require.Equal(t, tc.mustMatch, tc.component.Matches(tc.identifier), "failed: %s", testCase)
	}
}
