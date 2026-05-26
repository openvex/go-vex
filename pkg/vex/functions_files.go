// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openvex/go-vex/pkg/csaf"
)

// Load reads the VEX document file at the given path and returns a decoded VEX
// object. If Load is unable to read the file or decode the document, it returns
// an error.
func Load(path string) (*VEX, error) {
	data, err := os.ReadFile(path) //nolint:gosec // This is supposed to open user-specified paths
	if err != nil {
		return nil, fmt.Errorf("loading VEX file: %w", err)
	}

	return Parse(data)
}

// Parse parses an OpenVEX document in the latest version from the data byte array.
func Parse(data []byte) (*VEX, error) {
	vexDoc := &VEX{}
	if err := json.Unmarshal(data, vexDoc); err != nil {
		return nil, fmt.Errorf("%s: %w", errMsgParse, err)
	}
	return vexDoc, nil
}

// OpenYAML opens a VEX file in YAML format.
func OpenYAML(path string) (*VEX, error) {
	data, err := os.ReadFile(path) //nolint:gosec // This is supposed to open user-specified paths
	if err != nil {
		return nil, fmt.Errorf("opening YAML file: %w", err)
	}
	vexDoc := New()
	if err := yaml.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling VEX data: %w", err)
	}
	return &vexDoc, nil
}

// OpenJSON opens an OpenVEX file in JSON format.
func OpenJSON(path string) (*VEX, error) {
	data, err := os.ReadFile(path) //nolint:gosec // This is supposed to open user-specified paths
	if err != nil {
		return nil, fmt.Errorf("opening JSON file: %w", err)
	}
	vexDoc := New()
	if err := json.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling VEX data: %w", err)
	}
	return &vexDoc, nil
}

// parseContext light parses a JSON document to look for the OpenVEX context locator
func parseContext(rawDoc []byte) (string, error) {
	pd := struct {
		Context string `json:"@context"`
	}{}

	if err := json.Unmarshal(rawDoc, &pd); err != nil {
		return "", fmt.Errorf("parsing context from json data: %w", err)
	}

	if strings.HasPrefix(pd.Context, Context) {
		return pd.Context, nil
	}
	return "", nil
}

// Open tries to autodetect the vex format and open it
func Open(path string) (*VEX, error) {
	data, err := os.ReadFile(path) //nolint:gosec // This is supposed to open user-specified paths
	if err != nil {
		return nil, fmt.Errorf("opening VEX file: %w", err)
	}

	documentContextLocator, err := parseContext(data)
	if err != nil {
		return nil, err
	}

	if documentContextLocator == ContextLocator() {
		return Parse(data)
	} else if documentContextLocator != "" {
		version := strings.TrimPrefix(documentContextLocator, Context)
		version = strings.TrimPrefix(version, "/")

		// If version is nil, then we assume v0.0.1
		if version == "" {
			version = "v0.0.1"
		}

		parser := getLegacyVersionParser(version)
		if parser == nil {
			return nil, fmt.Errorf("unable to get parser for version %s", version)
		}

		doc, err := parser(data)
		if err != nil {
			return nil, fmt.Errorf("parsing document: %w", err)
		}

		return doc, nil
	}

	if bytes.Contains(data, []byte(`"csaf_version"`)) {
		slog.Info("Abriendo CSAF")

		doc, err := OpenCSAF(path, []string{})
		if err != nil {
			return nil, fmt.Errorf("attempting to open csaf doc: %w", err)
		}
		return doc, nil
	}

	return nil, fmt.Errorf("unable to detect document format reading %s", path)
}

// OpenCSAF opens a CSAF document and builds a VEX object from it.
func OpenCSAF(path string, products []string) (*VEX, error) {
	csafDoc, err := csaf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening csaf doc: %w", err)
	}
	if err := csafDoc.ValidateProductStatuses(); err != nil {
		return nil, fmt.Errorf("validating csaf product statuses: %w", err)
	}

	productDict := map[string]csaf.Product{}
	filterDict := map[string]string{}
	for _, pid := range products {
		filterDict[pid] = pid
	}

	prods := csafDoc.ProductTree.ListProducts()
	for _, sp := range prods {
		// Check if we need to filter
		if len(filterDict) > 0 {
			foundID := false
			for _, i := range sp.IdentificationHelper {
				if _, ok := filterDict[i]; ok {
					foundID = true
					break
				}
			}
			_, ok := filterDict[sp.ID]
			if !foundID && !ok {
				continue
			}
		}

		productDict[sp.ID] = sp
	}

	// Create the VEX doc with the OpenVEX defaults, then carry over CSAF metadata.
	vexDoc := New()
	vexDoc.ID = csafDoc.Document.Tracking.ID
	vexDoc.Author = csafDoc.Document.Publisher.Name
	if !csafDoc.Document.Tracking.CurrentReleaseDate.IsZero() {
		vexDoc.Timestamp = &csafDoc.Document.Tracking.CurrentReleaseDate
	}

	// Cycle the CSAF vulns list and get those that apply
	for i := range csafDoc.Vulnerabilities {
		for status, docProducts := range csafDoc.Vulnerabilities[i].ProductStatus {
			for _, productID := range docProducts {
				if product, ok := productDict[productID]; ok {
					// Check we have a valid status
					vexStatus := StatusFromCSAF(string(status))
					if vexStatus == "" {
						return nil, fmt.Errorf("invalid status for product %s", productID)
					}

					stmt := Statement{
						Vulnerability: Vulnerability{Name: VulnerabilityID(csafDoc.Vulnerabilities[i].CVE)},
						Status:        vexStatus,
						StatusNotes:   fmt.Sprintf("CSAF product_status: %s", status),
						Products: []Product{
							{
								Component: componentFromCSAFProduct(product),
							},
						},
					}

					switch vexStatus {
					case StatusAffected:
						stmt.ActionStatement = actionStatementForProduct(csafDoc.Vulnerabilities[i], productID)
						if stmt.ActionStatement == "" {
							stmt.ActionStatement = NoActionStatementMsg
						}
					case StatusNotAffected:
						stmt.ImpactStatement = impactStatementForProduct(csafDoc.Vulnerabilities[i], productID)
					}

					vexDoc.Statements = append(vexDoc.Statements, stmt)
				}
			}
		}
	}

	return &vexDoc, nil
}

func componentFromCSAFProduct(product csaf.Product) Component {
	component := Component{
		ID: product.ID,
	}

	if purl := product.IdentificationHelper["purl"]; purl != "" {
		component.ID = purl
		component.Identifiers = map[IdentifierType]string{
			PURL: purl,
		}
	}

	if cpe := product.IdentificationHelper["cpe"]; cpe != "" {
		if component.ID == product.ID {
			component.ID = cpe
		}
		if component.Identifiers == nil {
			component.Identifiers = map[IdentifierType]string{}
		}
		switch {
		case strings.HasPrefix(cpe, "cpe:2.3:"):
			component.Identifiers[CPE23] = cpe
		case strings.HasPrefix(cpe, "cpe:/"):
			component.Identifiers[CPE22] = cpe
		}
	}

	return component
}

func actionStatementForProduct(vuln csaf.Vulnerability, productID string) string {
	for _, remediation := range vuln.Remediations {
		if productIDMatches(remediation.ProductIDs, productID) {
			return remediation.Details
		}
	}
	return ""
}

func impactStatementForProduct(vuln csaf.Vulnerability, productID string) string {
	for _, threat := range vuln.Threats {
		if productIDMatches(threat.ProductIDs, productID) {
			return threat.Details
		}
	}
	return ""
}

func productIDMatches(productIDs []string, productID string) bool {
	for _, id := range productIDs {
		if id == productID {
			return true
		}
	}
	return false
}

// MergeFilesWithOptions opens a list of vex documents and after parsing them
// merges them into a single file using the specified merge options.
func MergeFilesWithOptions(mergeOpts *MergeOptions, filePaths []string) (*VEX, error) {
	vexDocs := []*VEX{}
	for i := range filePaths {
		doc, err := Open(filePaths[i])
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", filePaths[i], err)
		}
		vexDocs = append(vexDocs, doc)
	}
	doc, err := MergeDocumentsWithOptions(mergeOpts, vexDocs)
	if err != nil {
		return nil, fmt.Errorf("merging opened files: %w", err)
	}
	return doc, nil
}

// MergeFiles is a convenience wrapper around MergeFilesWithOptions that
// does not take options but performs the merge using the default options
func MergeFiles(filePaths []string) (*VEX, error) {
	return MergeFilesWithOptions(&MergeOptions{}, filePaths)
}
