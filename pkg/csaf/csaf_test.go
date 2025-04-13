// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "Example VEX Document", doc.Document.Title)
	require.Equal(t, "CSAFPID-0001", doc.FirstProductName())

	// Vulnerabilities
	require.Len(t, doc.Vulnerabilities, 2)
	require.Equal(t, "CVE-2009-4487", doc.Vulnerabilities[0].CVE)
	require.Equal(t, "CSAFPID-0001", doc.Vulnerabilities[0].ProductStatus["known_not_affected"][0])
	require.Equal(t, "CVE-2009-4488", doc.Vulnerabilities[1].CVE)
	require.Equal(t, "https://example.com/foo/v1.2.3/mitigation", doc.Vulnerabilities[1].Remediations[0].URL)
}

func TestOpenRHAdvisory(t *testing.T) {
	doc, err := Open("testdata/rhsa-2020_1358.json")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "Red Hat Security Advisory: virt:rhel security and bug fix update", doc.Document.Title)
	require.Equal(t, "AppStream-8.1.0.Z.MAIN.EUS", doc.FirstProductName())

	require.Equal(t, "https://bugzilla.redhat.com/show_bug.cgi?id=1794290", doc.Vulnerabilities[0].IDs[0].Text)

	// Publisher
	require.Equal(t, "vendor", doc.Document.Publisher.Category)
	require.Equal(t, "https://access.redhat.com/security/team/contact/", doc.Document.Publisher.ContactDetails)
	require.Equal(t, "Red Hat Product Security is responsible for vulnerability handling across all Red Hat offerings.", doc.Document.Publisher.IssuingAuthority)
	require.Equal(t, "https://www.redhat.com", doc.Document.Publisher.Namespace)
}

func TestFindFirstProduct(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	require.NoError(t, err)
	require.NotNil(t, doc)

	prod := doc.ProductTree.FindFirstProduct()
	require.Equal(t, "CSAFPID-0001", prod)
}

func TestFindByHelper(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	require.NoError(t, err)
	require.NotNil(t, doc)

	prod := doc.ProductTree.FindProductIdentifier("purl", "pkg:maven/@1.3.4")
	require.NotNil(t, prod)
	require.Equal(t, "CSAFPID-0001", prod.ID)
}

func TestListProducts(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	require.NoError(t, err)
	require.NotNil(t, doc)
	prods := doc.ProductTree.Branches[0].Branches[0].Branches[0].ListProducts()
	require.Len(t, prods, 1)
	require.Equal(t, "pkg:golang/github.com/go-homedir@v1.1.0", prods[0].IdentificationHelper["purl"])
	require.Len(t, doc.ProductTree.Relationships, 1)

	allProds := doc.ProductTree.Branches[0].ListProducts()
	require.NotNil(t, allProds)
	require.Len(t, allProds, 3)
}
