// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/csaf"
)

func TestParse(t *testing.T) {
	for m, tc := range map[string]struct {
		path      string
		product   string
		vulns     []string
		shouldErr bool
	}{
		// Previous versions fail on test
		"OpenVEX v0.0.1": {testV001Path, "", []string{}, true},
		// Current version
		"OpenVEX v0.2.0": {"testdata/v0.2.0.json", testAlpineOCIPURL, []string{testCVE20231255, "CVE-2023-2650", "CVE-2023-2975", "CVE-2023-3446", "CVE-2023-3817"}, false},
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

		vulns := make([]string, 0, len(doc.Statements))
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
	vexDoc, err := OpenCSAF(testCSAFPath, []string{})
	require.NoError(t, err)
	require.Len(t, vexDoc.Statements, 1)
	require.Len(t, vexDoc.Statements[0].Products, 1)
	require.Equal(t, "CVE-2009-4487", string(vexDoc.Statements[0].Vulnerability.Name))
	require.Equal(t, StatusNotAffected, vexDoc.Statements[0].Status)
	require.Equal(t, ContextLocator(), vexDoc.Context)
	require.Equal(t, 1, vexDoc.Version)
	require.Equal(t, "2022-EVD-UC-01-NA-001", vexDoc.ID)
}

func TestOpenCSAF(t *testing.T) {
	for _, tc := range []struct {
		doc string
		len int
		id  []string
	}{
		{testCSAFPath, 1, []string{"CSAFPID-0001"}},
		{testCSAFPath, 1, []string{"pkg:golang/github.com/go-homedir@v1.2.0"}},
	} {
		doc, err := OpenCSAF(tc.doc, tc.id)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Len(t, doc.Statements, tc.len)
	}
}

func TestOpenCSAFProductStatuses(t *testing.T) {
	t.Parallel()

	doc, err := OpenCSAF("../csaf/testdata/product-statuses.json", []string{})
	require.NoError(t, err)
	require.Len(t, doc.Statements, 8)

	statements := map[string]Statement{}
	for _, stmt := range doc.Statements {
		csafStatus := strings.TrimPrefix(stmt.StatusNotes, "CSAF product_status: ")
		statements[csafStatus] = stmt
	}

	for _, status := range []csaf.ProductStatusName{
		csaf.ProductStatusFirstAffected,
		csaf.ProductStatusKnownAffected,
		csaf.ProductStatusLastAffected,
	} {
		stmt := statements[string(status)]
		require.Equal(t, StatusAffected, stmt.Status, status)
		require.Equal(t, "Update "+string(status), stmt.ActionStatement, status)
	}

	for _, status := range []csaf.ProductStatusName{
		csaf.ProductStatusFirstFixed,
		csaf.ProductStatusFixed,
		csaf.ProductStatusRecommended,
	} {
		stmt := statements[string(status)]
		require.Equal(t, StatusFixed, stmt.Status, status)
		require.Empty(t, stmt.ActionStatement, status)
	}

	notAffected := statements[string(csaf.ProductStatusKnownNotAffected)]
	require.Equal(t, StatusNotAffected, notAffected.Status)
	require.Equal(t, "Impact for known_not_affected", notAffected.ImpactStatement)
	require.Empty(t, notAffected.ActionStatement)

	underInvestigation := statements[string(csaf.ProductStatusUnderInvestigation)]
	require.Equal(t, StatusUnderInvestigation, underInvestigation.Status)
	require.Empty(t, underInvestigation.ActionStatement)

	lastAffected := statements[string(csaf.ProductStatusLastAffected)]
	require.Equal(t, "pkg:generic/example/last_affected@1.0.0", lastAffected.Products[0].ID)
	require.Equal(t, "pkg:generic/example/last_affected@1.0.0", lastAffected.Products[0].Identifiers[PURL])
}

func TestOpen(t *testing.T) {
	for m, tc := range map[string]struct {
		path      string
		shouldErr bool
	}{
		"OpenVEX v0.0.1":              {testV001Path, false},
		"OpenVEX v0.0.1 (no version)": {"testdata/v0.0.1-noversion.json", false},
		"OpenVEX v0.2.0":              {"testdata/v0.2.0.json", false},
		"CSAF document":               {testCSAFPath, false},
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
