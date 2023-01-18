/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/sirupsen/logrus"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"

	"github.com/openvex/go-vex/pkg/csaf"
)

const (
	// TypeURI is the type used to describe VEX documents, e.g. within [in-toto
	// statements].
	//
	// [in-toto statements]: https://github.com/in-toto/attestation/blob/main/spec/README.md#statement
	TypeURI = "https://openvex.dev/ns"

	// DefaultAuthor is the default value for a document's Author field.
	DefaultAuthor = "Unknown Author"

	// DefaultRole is the default value for a document's AuthorRole field.
	DefaultRole = "Document Creator"

	// Context is the URL of the json-ld context definition
	Context = "https://openvex.dev/ns"

	// PublicNamespace is the public openvex namespace for common @ids
	PublicNamespace = "https://openvex.dev/docs"

	// NoActionStatementMsg is the action statement that informs that there is no action statement :/
	NoActionStatementMsg = "No action statement provided"
)

// The VEX type represents a VEX document and all of its contained information.
type VEX struct {
	Metadata
	Statements []Statement `json:"statements"`
}

// The Metadata type represents the metadata associated with a VEX document.
type Metadata struct {
	// Context is the URL pointing to the jsonld context definition
	Context string `json:"@context"`

	// ID is the identifying string for the VEX document. This should be unique per
	// document.
	ID string `json:"@id"`

	// Author is the identifier for the author of the VEX statement, ideally a common
	// name, may be a URI. [author] is an individual or organization. [author]
	// identity SHOULD be cryptographically associated with the signature of the VEX
	// statement or document or transport.
	Author string `json:"author"`

	// AuthorRole describes the role of the document Author.
	AuthorRole string `json:"role"`

	// Timestamp defines the time at which the document was issued.
	Timestamp *time.Time `json:"timestamp"`

	// Version is the document version. It must be incremented when any content
	// within the VEX document changes, including any VEX statements included within
	// the VEX document.
	Version string `json:"version"`

	// Tooling expresses how the VEX document and contained VEX statements were
	// generated. It's optional. It may specify tools or automated processes used in
	// the document or statement generation.
	Tooling string `json:"tooling,omitempty"`

	// Supplier is an optional field.
	Supplier string `json:"supplier,omitempty"`
}

// New returns a new, initialized VEX document.
func New() VEX {
	now := time.Now()
	t, err := DateFromEnv()
	if err != nil {
		logrus.Warn(err)
	}
	if t != nil {
		now = *t
	}
	return VEX{
		Metadata: Metadata{
			Context:    Context,
			Author:     DefaultAuthor,
			AuthorRole: DefaultRole,
			Version:    "1",
			Timestamp:  &now,
		},
		Statements: []Statement{},
	}
}

// Load reads the VEX document file at the given path and returns a decoded VEX
// object. If Load is unable to read the file or decode the document, it returns
// an error.
func Load(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading VEX file: %w", err)
	}

	vexDoc := &VEX{}
	if err := json.Unmarshal(data, vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshaling VEX document: %w", err)
	}
	return vexDoc, nil
}

// OpenYAML opens a VEX file in YAML format.
func OpenYAML(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening YAML file: %w", err)
	}
	vexDoc := New()
	if err := yaml.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling VEX data: %w", err)
	}
	return &vexDoc, nil
}

// OpenJSON opens a VEX file in JSON format.
func OpenJSON(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening JSON file: %w", err)
	}
	vexDoc := New()
	if err := json.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling VEX data: %w", err)
	}
	return &vexDoc, nil
}

// ToJSON serializes the VEX document to JSON and writes it to the passed writer.
func (vexDoc *VEX) ToJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(vexDoc); err != nil {
		return fmt.Errorf("encoding vex document: %w", err)
	}
	return nil
}

// OpenHCL opens a VEX file in HCL format.
//
// # Example
//
//	author      = "Wolfi J. Inkinson"
//	author_role = "Senior VEXing Engineer"
//	timestamp   = "2023-01-09T21:23:03.579712389-06:00"
//	version     = "1"
//
//	statement "CVE-1234-5678" {
//	  products = [
//	    "pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"
//	  ]
//	  subcomponents = [
//	    "pkg:apk/alpine/git@2.38.1-r0?arch=x86_64",
//	    "pkg:apk/alpine/git@2.38.1-r0?arch=ppc64le"
//	  ]
//	  status = "not_affected"
//	  justification = "inline_mitigations_already_exist"
//	  impact_statement = "Included git is mitigated against CVE-2023-12345 !"
//	}
func OpenHCL(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening HCL file: %w", err)
	}

	vexDoc := New()

	f, diags := hclsyntax.ParseConfig(data, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing HCL file: %w", diags)
	}

	c, diags := f.Body.Content(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "context"},
			{Name: "id"},
			{Name: "author"},
			{Name: "author_role"},
			{Name: "timestamp"},
			{Name: "version"},
			{Name: "tooling"},
			{Name: "supplier"},
		},
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type: "statement",
				LabelNames: []string{
					"vulnerability",
				},
			},
		},
	})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing HCL file: %s", err.Error())
	}

	for _, attr := range c.Attributes {
		switch attr.Name {
		case "context":
			context, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parsing HCL file: %s", diags.Error())
			}
			vexDoc.Context = context.AsString()
		case "id":
			id, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parsing HCL file: %s", diags.Error())
			}
			vexDoc.ID = id.AsString()
		case "author":
			author, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parsing HCL file: %s", diags.Error())
			}
			vexDoc.Metadata.Author = author.AsString()
		case "author_role":
			authorRole, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parsing HCL file: %s", diags.Error())
			}
			vexDoc.Metadata.AuthorRole = authorRole.AsString()
		case "timestamp":
			timestamp, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parsing HCL file: %s", diags.Error())
			}
			// Parse the timestamp as a string and then convert it to a time.Time.
			t, err := time.Parse(time.RFC3339Nano, timestamp.AsString())
			if err != nil {
				return nil, fmt.Errorf("parsing HCL file: %s", diags.Error())
			}
			vexDoc.Metadata.Timestamp = &t
		case "version":
			version, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parsing HCL file: %s", diags.Error())
			}
			vexDoc.Metadata.Version = version.AsString()
		}
	}

	parseStatementBlock := func(block *hcl.Block) (Statement, error) {
		s := Statement{}

		c, diags := block.Body.Content(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{
				{Name: "status"},
				{Name: "justification"},
				{Name: "impact_statement"},
				{Name: "products"},
				{Name: "subcomponents"},
			},
		})
		if diags.HasErrors() {
			return s, fmt.Errorf("parsing HCL file: %s", diags.Error())
		}

		for _, attr := range c.Attributes {
			switch attr.Name {
			case "vulnerability":
				vulnerability, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					return s, fmt.Errorf("parsing HCL file: %s", diags.Error())
				}
				s.Vulnerability = vulnerability.AsString()
			case "status":
				status, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					return s, fmt.Errorf("parsing HCL file: %s", diags.Error())
				}
				s.Status = Status(status.AsString())
			case "justification":
				justification, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					return s, fmt.Errorf("parsing HCL file: %s", diags.Error())
				}
				s.Justification = Justification(justification.AsString())
			case "impact_statement":
				impactStatement, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					return s, fmt.Errorf("parsing HCL file: %s", diags.Error())
				}
				s.ImpactStatement = impactStatement.AsString()
			case "products":
				products, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					return s, fmt.Errorf("parsing HCL file: %s", diags.Error())
				}
				s.Products = func() []string {
					var p []string
					for _, product := range products.AsValueSlice() {
						p = append(p, product.AsString())
					}
					return p
				}()
			case "subcomponents":
				subcomponents, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					return s, fmt.Errorf("parsing HCL file: %s", diags.Error())
				}
				s.Subcomponents = func() []string {
					var p []string
					for _, subcomponent := range subcomponents.AsValueSlice() {
						p = append(p, subcomponent.AsString())
					}
					return p
				}()
			}
		}

		return s, nil
	}

	for _, block := range c.Blocks {
		switch block.Type {
		case "statement":
			s, err := parseStatementBlock(block)
			if err != nil {
				return nil, fmt.Errorf("parsing HCL file: %s", err.Error())
			}
			s.Vulnerability = block.Labels[0] // The block label is the vulnerability ID.
			vexDoc.Statements = append(vexDoc.Statements, s)
		}
	}

	return &vexDoc, nil
}

// ToHCL serializes the VEX document to HCL and writes it to the passed writer.
func (vexDoc *VEX) ToHCL(w io.Writer) error {
	f := hclwrite.NewEmptyFile()

	// Write the document metadata.
	if vexDoc.Metadata.Context != "" {
		f.Body().SetAttributeValue("context", cty.StringVal(vexDoc.Metadata.Context))
	}

	if vexDoc.Metadata.ID != "" {
		f.Body().SetAttributeValue("id", cty.StringVal(vexDoc.Metadata.ID))
	}

	if vexDoc.Metadata.Author != "" {
		f.Body().SetAttributeValue("title", cty.StringVal(vexDoc.Metadata.Author))
	}

	if vexDoc.Metadata.AuthorRole != "" {
		f.Body().SetAttributeValue("author_role", cty.StringVal(vexDoc.Metadata.AuthorRole))
	}

	if vexDoc.Metadata.Version != "" {
		f.Body().SetAttributeValue("version", cty.StringVal(vexDoc.Metadata.Version))
	}

	if vexDoc.Metadata.Timestamp != nil {
		f.Body().SetAttributeValue("timestamp", cty.StringVal(vexDoc.Metadata.Timestamp.Format(time.RFC3339)))
	}

	if vexDoc.Metadata.Tooling != "" {
		f.Body().SetAttributeValue("tooling", cty.StringVal(vexDoc.Metadata.Tooling))
	}
	if vexDoc.Metadata.Supplier != "" {
		f.Body().SetAttributeValue("supplier", cty.StringVal(vexDoc.Metadata.Supplier))
	}

	// Write document statements.
	for _, statement := range vexDoc.Statements {
		statementBlock := f.Body().AppendNewBlock("statement", []string{statement.Vulnerability})

		if statement.VulnDescription != "" {
			statementBlock.Body().SetAttributeValue("vuln_description", cty.StringVal(statement.VulnDescription))
		}

		if statement.ImpactStatement != "" {
			statementBlock.Body().SetAttributeValue("impact", cty.StringVal(statement.ImpactStatement))
		}

		if statement.Timestamp != nil {
			statementBlock.Body().SetAttributeValue("timestamp", cty.StringVal(statement.Timestamp.Format(time.RFC3339)))
		}

		if len(statement.Products) > 0 {
			statementBlock.Body().SetAttributeValue("products", cty.ListVal(func() (vals []cty.Value) {
				for _, product := range statement.Products {
					vals = append(vals, cty.StringVal(product))
				}
				return vals
			}()))
		}

		if len(statement.Subcomponents) > 0 {
			statementBlock.Body().SetAttributeValue("subcomponents", cty.ListVal(func() (vals []cty.Value) {
				for _, subcomponent := range statement.Subcomponents {
					vals = append(vals, cty.StringVal(subcomponent))
				}
				return vals
			}()))
		}

		if statement.Status != "" {
			statementBlock.Body().SetAttributeValue("status", cty.StringVal(string(statement.Status)))
		}

		if statement.StatusNotes != "" {
			statementBlock.Body().SetAttributeValue("status_notes", cty.StringVal(statement.StatusNotes))
		}

		if statement.Justification != "" {
			statementBlock.Body().SetAttributeValue("justification", cty.StringVal(string(statement.Justification)))
		}

		if statement.ImpactStatement != "" {
			statementBlock.Body().SetAttributeValue("impact_statement", cty.StringVal(statement.ImpactStatement))
		}

		if statement.ActionStatement != "" {
			statementBlock.Body().SetAttributeValue("action_statement", cty.StringVal(statement.ActionStatement))
		}

		if statement.ActionStatementTimestamp != nil {
			statementBlock.Body().SetAttributeValue("action_statement_timestamp", cty.StringVal(statement.ActionStatementTimestamp.Format(time.RFC3339)))
		}
	}

	_, err := f.WriteTo(w)
	if err != nil {
		return fmt.Errorf("failed to write VEX HCL: %w", err)
	}

	return nil
}

// StatementFromID returns a statement for a given vulnerability if there is one.
func (vexDoc *VEX) StatementFromID(id string) *Statement {
	for _, statement := range vexDoc.Statements { //nolint:gocritic // turning off for rule rangeValCopy
		if statement.Vulnerability == id {
			logrus.Infof("VEX doc contains statement for CVE %s", id)
			return &statement
		}
	}
	return nil
}

// SortDocuments sorts and returns a slice of documents based on their date.
// VEXes should be applied sequentially in chronological order as they capture
// knowledge about an artifact as it changes over time.
func SortDocuments(docs []*VEX) []*VEX {
	sort.Slice(docs, func(i, j int) bool {
		if docs[j].Timestamp == nil {
			return true
		}
		if docs[i].Timestamp == nil {
			return false
		}
		return docs[i].Timestamp.Before(*(docs[j].Timestamp))
	})
	return docs
}

// OpenCSAF opens a CSAF document and builds a VEX object from it.
func OpenCSAF(path string, products []string) (*VEX, error) {
	csafDoc, err := csaf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening csaf doc: %w", err)
	}

	productDict := map[string]string{}
	for _, pid := range products {
		productDict[pid] = pid
	}

	// If no products were specified, we use the first one
	if len(products) == 0 {
		p := csafDoc.FirstProductName()
		if p == "" {
			// Error? I think so.
			return nil, errors.New("unable to find a product ID in CSAF document")
		}
		productDict[p] = p
	}

	// Create the vex doc
	v := &VEX{
		Metadata: Metadata{
			ID:         csafDoc.Document.Tracking.ID,
			Author:     "",
			AuthorRole: "",
			Timestamp:  &time.Time{},
		},
		Statements: []Statement{},
	}

	// Cycle the CSAF vulns list and get those that apply
	for _, c := range csafDoc.Vulnerabilities {
		for status, docProducts := range c.ProductStatus {
			for _, productID := range docProducts {
				if _, ok := productDict[productID]; ok {
					// Check we have a valid status
					if StatusFromCSAF(status) == "" {
						return nil, fmt.Errorf("invalid status for product %s", productID)
					}

					// TODO search the threats struct for justification, etc
					just := ""
					for _, t := range c.Threats {
						// Search the threats for a justification
						for _, p := range t.ProductIDs {
							if p == productID {
								just = t.Details
							}
						}
					}

					v.Statements = append(v.Statements, Statement{
						Vulnerability:   c.CVE,
						Status:          StatusFromCSAF(status),
						Justification:   "", // Justifications are not machine readable in csaf, it seems
						ActionStatement: just,
						Products:        products,
					})
				}
			}
		}
	}

	return v, nil
}

// CanonicalHash returns a hash representing the state of impact statements
// expressed in it. This hash should be constant as long as the impact
// statements are not modified. Changes in extra information and metadata
// will not alter the hash.
func (vexDoc *VEX) CanonicalHash() (string, error) {
	// Here's the algo:

	// 1. Start with the document date. In unixtime to avoid format variance.
	cString := fmt.Sprintf("%d", vexDoc.Timestamp.Unix())

	// 2. Document version
	cString += fmt.Sprintf(":%s", vexDoc.Version)

	// 3. Sort the statements
	stmts := vexDoc.Statements
	SortStatements(stmts, *vexDoc.Timestamp)

	// 4. Now add the data from each statement
	//nolint:gocritic
	for _, s := range stmts {
		// 4a. Vulnerability
		cString += fmt.Sprintf(":%s", s.Vulnerability)
		// 4b. Status + Justification
		cString += fmt.Sprintf(":%s:%s", s.Status, s.Justification)
		// 4c. Statement time, in unixtime. If it exists, if not the doc's
		if s.Timestamp != nil {
			cString += fmt.Sprintf(":%d", s.Timestamp.Unix())
		} else {
			cString += fmt.Sprintf(":%d", vexDoc.Timestamp.Unix())
		}
		// 4d. Sorted products
		prods := s.Products
		sort.Strings(prods)
		cString += fmt.Sprintf(":%s", strings.Join(prods, ":"))
	}

	// 5. Hash the string in sha256 and return
	h := sha256.New()
	if _, err := h.Write([]byte(cString)); err != nil {
		return "", fmt.Errorf("hashing canonicalization string: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// GenerateCanonicalID generates an ID for the document. The ID will be
// based on the canonicalization hash. This means that documents
// with the same impact statements will always get the same ID.
// Trying to generate the id of a doc with an existing ID will
// not do anything.
func (vexDoc *VEX) GenerateCanonicalID() (string, error) {
	if vexDoc.ID != "" {
		return vexDoc.ID, nil
	}
	cHash, err := vexDoc.CanonicalHash()
	if err != nil {
		return "", fmt.Errorf("getting canonical hash: %w", err)
	}

	// For common namespaced documents we namespace them into /public
	vexDoc.ID = fmt.Sprintf("%s/public/vex-%s", PublicNamespace, cHash)
	return vexDoc.ID, nil
}

func DateFromEnv() (*time.Time, error) {
	// Support envvar for reproducible vexing
	d := os.Getenv("SOURCE_DATE_EPOCH")
	if d == "" {
		return nil, nil
	}

	var t time.Time
	sec, err := strconv.ParseInt(d, 10, 64)
	if err == nil {
		t = time.Unix(sec, 0)
	} else {
		t, err = time.Parse(time.RFC3339, d)
		if err != nil {
			return nil, fmt.Errorf("failed to parse envvar SOURCE_DATE_EPOCH: %w", err)
		}
	}
	return &t, nil
}
