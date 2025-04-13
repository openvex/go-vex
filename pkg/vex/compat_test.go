// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestParse001(t *testing.T) {
	d, err := time.Parse(time.RFC3339, "2023-01-08T18:02:03.647787998-06:00")
	require.NoError(t, err)
	for msg, tc := range map[string]struct {
		path      string
		shouldErr bool
		expected  *VEX
	}{
		"normal": {
			"testdata/v0.0.1.json",
			false,
			&VEX{
				Metadata: Metadata{
					Context:    "https://openvex.dev/ns/v" + SpecVersion,
					ID:         "https://openvex.dev/docs/example/vex-9fb3463de1b57",
					Author:     "Wolfi J Inkinson",
					AuthorRole: "Document Creator",
					Timestamp:  &d,
					Version:    1,
				},
				Statements: []Statement{
					{
						Vulnerability: Vulnerability{Name: "CVE-2023-12345"},
						Products: []Product{
							{Component: Component{ID: "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"}, Subcomponents: []Subcomponent{}},
							{Component: Component{ID: "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64"}, Subcomponents: []Subcomponent{}},
						},
						Status: "fixed",
					},
				},
			},
		},
	} {
		data, err := os.ReadFile(tc.path)
		require.NoError(t, err, msg)
		doc, err := parse001(data)
		if tc.shouldErr {
			require.Error(t, err, msg)
			return
		}

		require.True(t, cmp.Equal(doc.Metadata, tc.expected.Metadata), "%+v + %+v", doc.Metadata, tc.expected.Metadata)
		require.Equal(t, doc.Statements, tc.expected.Statements, "%+v + %+v", doc.Statements, tc.expected.Statements)
		require.True(t, cmp.Equal(doc, tc.expected), msg)

		require.NoError(t, err, msg)
	}
}
