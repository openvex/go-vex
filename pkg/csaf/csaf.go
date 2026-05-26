// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// CSAF is a Common Security Advisory Framework Version 2.0 document.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
type CSAF struct {
	// Document contains metadata about the CSAF document itself.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321-document-property
	Document DocumentMetadata `json:"document"`

	// ProductTree contains information about the product tree (branches only).
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#322-product-tree-property
	ProductTree ProductBranch `json:"product_tree"`

	// Vulnerabilities contains information about the vulnerabilities,
	// (i.e. CVEs), associated threats, and product status.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323-vulnerabilities-property
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`

	// Notes holds notes associated with the whole document.
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3217-document-property---notes
	Notes []Note `json:"notes,omitempty"`
}

// DocumentMetadata contains metadata about the CSAF document itself.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321-document-property
type DocumentMetadata struct {
	Category    string      `json:"category,omitempty"`
	CSAFVersion string      `json:"csaf_version,omitempty"`
	Notes       []Note      `json:"notes,omitempty"`
	Title       string      `json:"title"`
	Tracking    Tracking    `json:"tracking"`
	References  []Reference `json:"references,omitempty"`
	Publisher   Publisher   `json:"publisher"`
}

// Document references holds a list of references associated with the whole document.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3219-document-property---references
type Reference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

// Tracking contains information used to track the CSAF document through its lifecycle.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32112-document-property---tracking
type Tracking struct {
	ID                 string     `json:"id"`
	CurrentReleaseDate time.Time  `json:"current_release_date"`
	InitialReleaseDate time.Time  `json:"initial_release_date"`
	RevisionHistory    []Revision `json:"revision_history,omitempty"`
	Status             string     `json:"status,omitempty"`
	Version            string     `json:"version,omitempty"`
	Generator          Generator  `json:"generator,omitempty,omitzero"`
}

// Revision contains information needed to track a document revision.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321126-revision-history-type---revision
type Revision struct {
	Date          time.Time `json:"date"`
	LegacyVersion string    `json:"legacy_version,omitempty"`
	Number        string    `json:"number"`
	Summary       string    `json:"summary"`
}

// Generator holds information about how the CSAF document was generated.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#321123-document-property---tracking---generator
type Generator struct {
	Date   time.Time `json:"date,omitempty,omitzero"`
	Engine Engine    `json:"engine"`
}

// Engine identifies the generator engine.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Publisher provides information on the publishing entity.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3218-document-property---publisher
type Publisher struct {
	Category         string `json:"category"`
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
}

// Vulnerability contains information about a CVE and its associated threats.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323-vulnerabilities-property
type Vulnerability struct {
	// MITRE standard Common Vulnerabilities and Exposures (CVE) tracking number for the vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3232-vulnerabilities-property---cve
	CVE string `json:"cve"`

	// List of IDs represents a list of unique labels or tracking IDs for the vulnerability (if such information exists).
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3236-vulnerabilities-property---ids
	IDs []TrackingID `json:"ids,omitempty"`

	// Provide details on the status of the referenced product related to the vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3239-vulnerabilities-property---product-status
	ProductStatus ProductStatus `json:"product_status,omitempty"`

	// Provide details of threats associated with a vulnerability.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32314-vulnerabilities-property---threats
	Threats []ThreatData `json:"threats,omitempty"`

	// Provide details of remediations associated with a Vulnerability
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32312-vulnerabilities-property---remediations
	Remediations []RemediationData `json:"remediations,omitempty"`

	// Machine readable flags for products related to vulnerability
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3235-vulnerabilities-property---flags
	Flags []Flag `json:"flags,omitempty"`

	// Vulnerability references holds a list of references associated with this vulnerability item.
	//
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32310-vulnerabilities-property---references
	References []Reference `json:"references,omitempty"`

	ReleaseDate time.Time `json:"release_date,omitempty,omitzero"`

	// Notes holds notes associated with the Vulnerability object.
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3238-vulnerabilities-property---notes
	Notes []Note `json:"notes,omitempty"`

	// Scores holds the scores associated with the Vulnerability object.
	// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32313-vulnerabilities-property---scores
	// Currently only CVSS v3 is supported.
	Scores []Score `json:"scores,omitempty"`
}

type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
	Audience string `json:"audience,omitempty"`
}

// Every ID item with the two mandatory properties System Name (system_name) and Text (text) contains a single unique label or tracking ID for the vulnerability.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3236-vulnerabilities-property---ids
type TrackingID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// ThreatData contains information about a threat to a product.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32314-vulnerabilities-property---threats
type ThreatData struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

// RemediationData contains information about how to remediate a vulnerability for a set of products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32312-vulnerabilities-property---remediations
type RemediationData struct {
	Category     string      `json:"category"`
	Date         time.Time   `json:"date,omitempty,omitzero"`
	Details      string      `json:"details"`
	Entitlements []string    `json:"entitlements,omitempty"`
	GroupIDs     []string    `json:"group_ids,omitempty"`
	ProductIDs   []string    `json:"product_ids,omitempty"`
	Restart      RestartData `json:"restart_required,omitempty,omitzero"`
	URL          string      `json:"url,omitempty"`
}

// Remediation instructions for restart of affected software.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323127-vulnerabilities-property---remediations---restart-required
type RestartData struct {
	Category string `json:"category"`
	Details  string `json:"details,omitempty"`
}

// Machine readable flags for products related to the Vulnerability
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3235-vulnerabilities-property---flags
type Flag struct {
	Label      string    `json:"label"`
	Date       time.Time `json:"date,omitempty,omitzero"`
	GroupIDs   []string  `json:"group_ids,omitempty"`
	ProductIDs []string  `json:"product_ids,omitempty"`
}

// ProductBranch is a recursive struct that contains information about a product and
// its nested products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3221-product-tree-property---branches
type ProductBranch struct {
	Category      string          `json:"category,omitempty"`
	Name          string          `json:"name,omitempty"`
	Branches      []ProductBranch `json:"branches,omitempty"`
	Product       Product         `json:"product,omitempty,omitzero"`
	Relationships []Relationship  `json:"relationships,omitempty"`
}

// Relationship establishes a link between two existing full_product_name_t elements, allowing
// the document producer to define a combination of two products that form a new full_product_name entry.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3224-product-tree-property---relationships
type Relationship struct {
	Category            string  `json:"category"`
	FullProductName     Product `json:"full_product_name"`
	ProductRef          string  `json:"product_reference"`
	RelatesToProductRef string  `json:"relates_to_product_reference"`
}

// Product contains information used to identify a product.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3124-branches-type---product
type Product struct {
	Name                 string            `json:"name"`
	ID                   string            `json:"product_id"`
	IdentificationHelper map[string]string `json:"product_identification_helper,omitempty"`
}

// Score contains score information tied to the listed products.
//
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32313-vulnerabilities-property---scores
type Score struct {
	CVSSV2     CVSSV2   `json:"cvss_v2"`
	CVSSV3     CVSSV3   `json:"cvss_v3"`
	ProductIDs []string `json:"products"`
}

// CVSSV2 describes CVSSv2.0 specification as defined here:
//   - https://www.first.org/cvss/cvss-v2.0.json
type CVSSV2 struct {
	AccessVector               string  `json:"accessVector"`
	AccessComplexity           string  `json:"accessComplexity"`
	Authentication             string  `json:"authentication"`
	ConfidentialityImpact      string  `json:"confidentialityImpact"`
	IntegrityImpact            string  `json:"integrityImpact"`
	AvailabilityImpact         string  `json:"availabilityImpact"`
	BaseScore                  float64 `json:"baseScore"`
	Exploitability             string  `json:"exploitability"`
	RemediationLevel           string  `json:"remediationLevel"`
	ReportConfidence           string  `json:"reportConfidence"`
	TemporalScore              float64 `json:"temporalScore"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential"`
	TargetDistribution         string  `json:"targetDistribution"`
	ConfidentialityRequirement string  `json:"confidentialityRequirement"`
	IntegrityRequirement       string  `json:"integrityRequirement"`
	AvailabilityRequirement    string  `json:"availabilityRequirement"`
	EnvironmentalScore         float64 `json:"environmentalScore"`
}

// CVSSV3 describes both the CVSSv3.0 and CVSSv3.1 specifications as defined here:
//   - https://www.first.org/cvss/cvss-v3.0.json
//   - https://www.first.org/cvss/cvss-v3.1.json
type CVSSV3 struct {
	AttackComplexity      string  `json:"attackComplexity"`
	AttackVector          string  `json:"attackVector"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	Scope                 string  `json:"scope"`
	UserInteraction       string  `json:"userInteraction"`
	VectorString          string  `json:"vectorString"`
	Version               string  `json:"version"`
}

// Open reads and parses a given file path and returns a CSAF document
// or an error if the file could not be opened or parsed.
func Open(path string) (*CSAF, error) {
	fh, err := os.Open(path) //nolint:gosec // This is supposed to open user-specified paths
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to open document: %w", err)
	}
	defer fh.Close() //nolint:errcheck

	csafDoc := &CSAF{}
	err = json.NewDecoder(fh).Decode(csafDoc)
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to decode document: %w", err)
	}

	return csafDoc, nil
}

// ToJSON serializes the CSAF document to JSON and writes it to the passed writer.
func (csafDoc *CSAF) ToJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(csafDoc); err != nil {
		return fmt.Errorf("encoding csaf document: %w", err)
	}
	return nil
}

// ValidateProductStatuses verifies that all vulnerability product_status
// buckets use CSAF-defined status names.
func (csafDoc *CSAF) ValidateProductStatuses() error {
	for i := range csafDoc.Vulnerabilities {
		if err := csafDoc.Vulnerabilities[i].ProductStatus.Validate(); err != nil {
			return fmt.Errorf("vulnerabilities[%d].product_status: %w", i, err)
		}
	}
	return nil
}

// FirstProductName returns the first product name in the product tree
// or an empty string if no product name is found.
func (csafDoc *CSAF) FirstProductName() string {
	return csafDoc.ProductTree.FindFirstProduct()
}

// FindFirstProduct recursively searches for the first product identifier in the tree
// and returns it or an empty string if no product identifier is found.
func (branch *ProductBranch) FindFirstProduct() string {
	if branch.Product.ID != "" {
		return branch.Product.ID
	}

	// No nested branches
	if branch.Branches == nil {
		return ""
	}

	// Recursively search for the first product	identifier
	for _, b := range branch.Branches {
		if p := b.FindFirstProduct(); p != "" {
			return p
		}
	}

	return ""
}

// FindFirstProductName recursively searches for the first product name in the tree
// and returns it or an empty string if no product name is found.
func (branch *ProductBranch) FindFirstProductName() string {
	if branch.Product.Name != "" {
		return branch.Product.Name
	}

	// No nested branches
	if branch.Branches == nil {
		return ""
	}

	// Recursively search for the first product	identifier
	for _, b := range branch.Branches {
		if p := b.FindFirstProductName(); p != "" {
			return p
		}
	}

	return ""
}

// FindProductIdentifier recursively searches for the first product identifier in the tree
func (branch *ProductBranch) FindProductIdentifier(helperType, helperValue string) *Product {
	if len(branch.Product.IdentificationHelper) != 0 {
		for k := range branch.Product.IdentificationHelper {
			if k != helperType {
				continue
			}
			if branch.Product.IdentificationHelper[k] == helperValue {
				return &branch.Product
			}
		}
	}

	// No nested branches
	if branch.Branches == nil {
		return nil
	}

	// Recursively search for the first identifier
	for _, b := range branch.Branches {
		if p := b.FindProductIdentifier(helperType, helperValue); p != nil {
			return p
		}
	}

	return nil
}

type ProductList []Product

// Add adds a product to the product list if its not there, matching id and
// software identifiers.
func (pl *ProductList) Add(p Product) {
	if p.ID == "" && len(p.IdentificationHelper) == 0 {
		return
	}
	helpers := map[string]struct{}{}

	for _, ih := range p.IdentificationHelper {
		helpers[ih] = struct{}{}
	}
	for _, tp := range *pl {
		if tp.ID == p.ID {
			return
		}
		for _, idhelper := range tp.IdentificationHelper {
			if _, ok := helpers[idhelper]; ok {
				return
			}
		}
	}
	*pl = append(ProductList{p}, *pl...)
}

// ListProducts returns a flat list of all products in the branch
func (branch *ProductBranch) ListProducts() ProductList {
	list := ProductList{}
	list.Add(branch.Product)
	for _, b := range branch.Branches {
		for _, p := range b.ListProducts() {
			list.Add(p)
		}
	}
	return list
}

func (csafDoc *CSAF) ListProducts() ProductList {
	prods := ProductList{}
	for _, b := range csafDoc.ProductTree.Branches {
		brachProds := b.ListProducts()
		for _, sp := range brachProds {
			prods.Add(sp)
		}
	}
	return prods
}
