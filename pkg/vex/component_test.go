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
			"madeup-2023-12345",
			&Component{
				Identifiers: map[IdentifierType]string{"customIdentifier": "madeup-2023-12345"},
			},
			true,
		},
		"wrong misc identifier": {
			"madeup-2023-12345",
			&Component{
				Identifiers: map[IdentifierType]string{"customIdentifier": "another-string"},
			},
			false,
		},
		"same purl": {
			"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64",
			&Component{
				Identifiers: map[IdentifierType]string{PURL: "pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64"},
			},
			true,
		},
		"globing purl": {
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			&Component{
				Identifiers: map[IdentifierType]string{PURL: "pkg:oci/curl"},
			},
			true,
		},
		"globing purl (inverse)": {
			"pkg:oci/curl",
			&Component{
				Identifiers: map[IdentifierType]string{
					PURL: "pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
				},
			},
			false,
		},
		"hash": {
			"77d86e9752cb933569dfa1f693ee4338e65b28b4",
			&Component{
				Hashes: map[Algorithm]Hash{
					SHA1: "77d86e9752cb933569dfa1f693ee4338e65b28b4",
				},
			},
			true,
		},
		"wrong hash": {
			"77d86e9752cb933569dfa1f693ee4338e65b28b4",
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
