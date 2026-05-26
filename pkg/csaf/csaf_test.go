// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestToJSONPreservesModeledCSAFFields(t *testing.T) {
	t.Parallel()

	data := []byte(`{
	  "document": {
	    "category": "csaf_vex",
	    "csaf_version": "2.0",
	    "distribution": {
	      "tlp": {
	        "label": "WHITE"
	      }
	    },
	    "publisher": {
	      "category": "vendor",
	      "name": "Example Company",
	      "namespace": "https://psirt.example.com"
	    },
	    "title": "Example VEX Document",
	    "tracking": {
	      "current_release_date": "2026-05-26T00:00:00Z",
	      "id": "EXAMPLE-2026-001",
	      "initial_release_date": "2026-05-26T00:00:00Z"
	    }
	  },
	  "product_tree": {},
	  "vulnerabilities": [
	    {
	      "cve": "CVE-2026-46598",
	      "title": "Example vulnerability",
	      "product_status": {
	        "last_affected": [
	          "CSAFPID-0001"
	        ]
	      }
	    }
	  ]
	}`)

	doc := &CSAF{}
	require.NoError(t, json.Unmarshal(data, doc))

	var output bytes.Buffer
	require.NoError(t, doc.ToJSON(&output))

	roundTrip := map[string]any{}
	require.NoError(t, json.Unmarshal(output.Bytes(), &roundTrip))

	document := roundTrip["document"].(map[string]any)
	distribution := document["distribution"].(map[string]any)
	tlp := distribution["tlp"].(map[string]any)
	require.Equal(t, "WHITE", tlp["label"])

	vulnerabilities := roundTrip["vulnerabilities"].([]any)
	vulnerability := vulnerabilities[0].(map[string]any)
	require.Equal(t, "Example vulnerability", vulnerability["title"])
}

func TestGoldenCSAFRoundTrip(t *testing.T) {
	t.Parallel()

	inputPath := filepath.Join("testdata", "product-statuses.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	doc, err := Open(inputPath)
	require.NoError(t, err)
	require.NoError(t, doc.ValidateProductStatuses())

	require.Equal(t, "csaf_vex", doc.Document.Category)
	require.Equal(t, "2.0", doc.Document.CSAFVersion)
	require.Equal(t, "WHITE", doc.Document.Distribution["tlp"].(map[string]any)["label"])
	require.Equal(t, "go-vex-test", doc.Document.Tracking.Generator.Engine.Name)
	require.Equal(t, "Example vulnerability covering CSAF product statuses", doc.Vulnerabilities[0].Title)

	for _, status := range ProductStatusNames() {
		require.NotEmpty(t, doc.Vulnerabilities[0].ProductStatus[status], status)
	}

	outputPath := filepath.Join(t.TempDir(), "product-statuses.json")
	fh, err := os.Create(outputPath)
	require.NoError(t, err)
	require.NoError(t, doc.ToJSON(fh))
	require.NoError(t, fh.Close())

	roundTrip, err := Open(outputPath)
	require.NoError(t, err)
	require.NoError(t, roundTrip.ValidateProductStatuses())

	outputData, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.JSONEq(t, string(inputData), string(outputData))
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

func TestFindFirstProductWhenBranchesAreEmpty(t *testing.T) {
	doc, err := Open("testdata/csaf.json")
	doc.ProductTree.Branches = []ProductBranch{}
	require.NoError(t, err)
	require.NotNil(t, doc)

	prod := doc.ProductTree.FindFirstProduct()
	require.Empty(t, prod)

	doc.ProductTree.Branches = nil
	emptyFirstProduct := doc.ProductTree.FindFirstProduct()
	require.Empty(t, emptyFirstProduct)
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

func TestAddEmptyProduct(t *testing.T) {
	product := Product{}
	list := ProductList{}
	list.Add(product)

	require.Empty(t, list)
}
