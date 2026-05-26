// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openvex/go-vex/pkg/csaf"
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

func TestOpenCSAFProductStatuses(t *testing.T) {
	t.Parallel()

	docPath := writeCSAFProductStatusFixture(t)

	doc, err := OpenCSAF(docPath, []string{})
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

func writeCSAFProductStatusFixture(t *testing.T) string {
	t.Helper()

	issuedAt := time.Date(2026, time.May, 26, 0, 0, 0, 0, time.UTC)
	statuses := []csaf.ProductStatusName{
		csaf.ProductStatusFirstAffected,
		csaf.ProductStatusFirstFixed,
		csaf.ProductStatusFixed,
		csaf.ProductStatusKnownAffected,
		csaf.ProductStatusKnownNotAffected,
		csaf.ProductStatusLastAffected,
		csaf.ProductStatusRecommended,
		csaf.ProductStatusUnderInvestigation,
	}

	branches := make([]csaf.ProductBranch, 0, len(statuses))
	productStatus := csaf.ProductStatus{}
	remediations := []csaf.RemediationData{}
	threats := []csaf.ThreatData{}

	for i, status := range statuses {
		productID := "CSAFPID-000" + string(rune('1'+i))
		purl := "pkg:generic/example/" + string(status) + "@1.0.0"

		productStatus[string(status)] = []string{productID}
		branches = append(branches, csaf.ProductBranch{
			Category: "product_version",
			Name:     string(status),
			Product: csaf.Product{
				Name: "Example " + string(status),
				ID:   productID,
				IdentificationHelper: map[string]string{
					"purl": purl,
				},
			},
		})

		if status.Affected() {
			remediations = append(remediations, csaf.RemediationData{
				Category:   "vendor_fix",
				Details:    "Update " + string(status),
				ProductIDs: []string{productID},
			})
		}
		if status == csaf.ProductStatusKnownNotAffected {
			threats = append(threats, csaf.ThreatData{
				Category:   "impact",
				Details:    "Impact for " + string(status),
				ProductIDs: []string{productID},
			})
		}
	}

	doc := csaf.CSAF{
		Document: csaf.DocumentMetadata{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Title:       "CSAF product status fixture",
			Publisher: csaf.Publisher{
				Category:  "vendor",
				Name:      "Example",
				Namespace: "https://example.com",
			},
			Tracking: csaf.Tracking{
				ID:                 "CSAF-PRODUCT-STATUS-FIXTURE",
				CurrentReleaseDate: issuedAt,
				InitialReleaseDate: issuedAt,
				RevisionHistory: []csaf.Revision{
					{
						Date:    issuedAt,
						Number:  "1",
						Summary: "Initial version.",
					},
				},
				Status:  "final",
				Version: "1",
			},
		},
		ProductTree: csaf.ProductBranch{
			Branches: []csaf.ProductBranch{
				{
					Category: "vendor",
					Name:     "Example",
					Branches: []csaf.ProductBranch{
						{
							Category: "product_name",
							Name:     "Example",
							Branches: branches,
						},
					},
				},
			},
		},
		Vulnerabilities: []csaf.Vulnerability{
			{
				CVE:           "CVE-2026-46598",
				ProductStatus: productStatus,
				Remediations:  remediations,
				Threats:       threats,
			},
		},
	}

	path := filepath.Join(t.TempDir(), "csaf.json")
	fh, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, doc.ToJSON(fh))
	require.NoError(t, fh.Close())

	return path
}
