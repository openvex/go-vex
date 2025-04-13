// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	for m, tc := range map[string]struct {
		path      string
		product   string
		vulns     []string
		shouldErr bool
	}{
		// Previous versions fail on test
		"OpenVEX v0.0.1": {"testdata/v0.0.1.json", "", []string{}, true},
		// Current version
		"OpenVEX v0.2.0": {"testdata/v0.2.0.json", "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126", []string{"CVE-2023-1255", "CVE-2023-2650", "CVE-2023-2975", "CVE-2023-3446", "CVE-2023-3817"}, false},
	} {
		data, err := os.ReadFile(tc.path)
		require.NoError(t, err)

		doc, err := Parse(data)
		if tc.shouldErr {
			require.Error(t, err, m)
			continue
		}

		require.NoError(t, err, "%s: reading %s", m, tc.path)
		require.NotNil(t, doc, m)

		require.Equal(t, doc.Context, ContextLocator())
		require.Len(t, doc.Statements, 5)

		vulns := []string{}
		for _, s := range doc.Statements {
			vulns = append(vulns, string(s.Vulnerability.Name))
			require.Equal(t, tc.product, s.Products[0].ID)
		}
		sort.Strings(vulns)
		require.Equal(t, vulns, tc.vulns, m)
	}
}

func TestLoadYAML(t *testing.T) {
	vexDoc, err := OpenYAML("testdata/vex.yaml")
	require.NoError(t, err)

	require.Len(t, vexDoc.Statements, 2)
}

func TestLoadCSAF(t *testing.T) {
	vexDoc, err := OpenCSAF("testdata/csaf.json", []string{})
	require.NoError(t, err)
	require.Len(t, vexDoc.Statements, 1)
	require.Len(t, vexDoc.Statements[0].Products, 1)
	require.Equal(t, "CVE-2009-4487", string(vexDoc.Statements[0].Vulnerability.Name))
	require.Equal(t, StatusNotAffected, vexDoc.Statements[0].Status)
	require.Equal(t, "2022-EVD-UC-01-NA-001", vexDoc.ID)
}

func TestOpenCSAF(t *testing.T) {
	for _, tc := range []struct {
		doc string
		len int
		id  []string
	}{
		{"testdata/csaf.json", 1, []string{"CSAFPID-0001"}},
		{"testdata/csaf.json", 1, []string{"pkg:golang/github.com/go-homedir@v1.2.0"}},
	} {
		doc, err := OpenCSAF(tc.doc, tc.id)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Len(t, doc.Statements, tc.len)
	}
}

func TestOpen(t *testing.T) {
	for m, tc := range map[string]struct {
		path      string
		shouldErr bool
	}{
		"OpenVEX v0.0.1":              {"testdata/v0.0.1.json", false},
		"OpenVEX v0.0.1 (no version)": {"testdata/v0.0.1-noversion.json", false},
		"OpenVEX v0.2.0":              {"testdata/v0.2.0.json", false},
		"CSAF document":               {"testdata/csaf.json", false},
	} {
		doc, err := Open(tc.path)
		if tc.shouldErr {
			require.Error(t, err, m)
			continue
		}

		require.NoError(t, err, m)
		require.NotNil(t, doc, m)
	}
}
