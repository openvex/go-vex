/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
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

	errMsgParse = "error"
)

// DefaultNamespace is the URL that will be used to generate new IRIs for generated
// documents and nodes. It is set to the OpenVEX public namespace by default.
var DefaultNamespace = PublicNamespace

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

	return Parse(data)
}

func Parse(data []byte) (*VEX, error) {
	vexDoc := &VEX{}
	if err := json.Unmarshal(data, vexDoc); err != nil {
		return nil, fmt.Errorf("%s: %w", errMsgParse, err)
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

// EffectiveStatement returns the latest VEX statement for a given product and
// vulnerability, that is the statement that contains the latest data about
// impact to a given product.
func (vexDoc *VEX) EffectiveStatement(product, vulnID string) (s *Statement) {
	statements := vexDoc.Statements
	var t time.Time
	if vexDoc.Timestamp != nil {
		t = *vexDoc.Timestamp
	}

	SortStatements(statements, t)

	for i := len(statements) - 1; i >= 0; i-- {
		if statements[i].Vulnerability.ID != vulnID {
			continue
		}
		for _, p := range statements[i].Products {
			if p.ID == product {
				return &statements[i]
			}
		}
	}
	return nil
}

// StatementFromID returns a statement for a given vulnerability if there is one.
//
// Deprecated: vex.StatementFromID is deprecated and will be removed in an upcoming version
func (vexDoc *VEX) StatementFromID(id string) *Statement {
	logrus.Warn("vex.StatementFromID is deprecated and will be removed in an upcoming version")
	for i := range vexDoc.Statements {
		if string(vexDoc.Statements[i].Vulnerability.Name) == id && len(vexDoc.Statements[i].Products) > 0 {
			return vexDoc.EffectiveStatement(vexDoc.Statements[i].Products[0].ID, id)
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

// Open tries to autodetect the vex format and open it
func Open(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening VEX file: %w", err)
	}

	if bytes.Contains(data, []byte(`"csaf_version"`)) {
		doc, err := OpenCSAF(path, []string{})
		if err != nil {
			return nil, fmt.Errorf("attempting to open csaf doc: %w", err)
		}
		return doc, nil
	}

	doc, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// OpenCSAF opens a CSAF document and builds a VEX object from it.
func OpenCSAF(path string, products []string) (*VEX, error) {
	csafDoc, err := csaf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening csaf doc: %w", err)
	}

	productDict := map[string]string{}
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

		for _, h := range sp.IdentificationHelper {
			productDict[sp.ID] = h
		}
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
	for i := range csafDoc.Vulnerabilities {
		for status, docProducts := range csafDoc.Vulnerabilities[i].ProductStatus {
			for _, productID := range docProducts {
				if _, ok := productDict[productID]; ok {
					// Check we have a valid status
					if StatusFromCSAF(status) == "" {
						return nil, fmt.Errorf("invalid status for product %s", productID)
					}

					// TODO search the threats struct for justification, etc
					just := ""
					for _, t := range csafDoc.Vulnerabilities[i].Threats {
						// Search the threats for a justification
						for _, p := range t.ProductIDs {
							if p == productID {
								just = t.Details
							}
						}
					}

					v.Statements = append(v.Statements, Statement{
						Vulnerability:   Vulnerability{Name: VulnerabilityID(csafDoc.Vulnerabilities[i].CVE)},
						Status:          StatusFromCSAF(status),
						Justification:   "", // Justifications are not machine readable in csaf, it seems
						ActionStatement: just,
						Products: []Product{
							{
								Component: Component{
									ID: productID,
								},
							},
						},
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

	// 3. Author identity
	cString += fmt.Sprintf(":%s", vexDoc.Author)

	// 4. Sort the statements
	stmts := vexDoc.Statements
	SortStatements(stmts, *vexDoc.Timestamp)

	// 5. Now add the data from each statement
	//nolint:gocritic
	for _, s := range stmts {
		// 4a. Vulnerability
		cString += cstringFromVulnerability(s.Vulnerability)
		// 4b. Status + Justification
		cString += fmt.Sprintf(":%s:%s", s.Status, s.Justification)
		// 4c. Statement time, in unixtime. If it exists, if not the doc's
		if s.Timestamp != nil {
			cString += fmt.Sprintf(":%d", s.Timestamp.Unix())
		} else {
			cString += fmt.Sprintf(":%d", vexDoc.Timestamp.Unix())
		}
		// 4d. Sorted product strings
		prods := []string{}
		for _, p := range s.Products {
			prodString := cstringFromComponent(p.Component)
			if p.Subcomponents != nil && len(p.Subcomponents) > 0 {
				for _, sc := range p.Subcomponents {
					prodString += cstringFromComponent(sc.Component)
				}
			}
			prods = append(prods, prodString)
		}
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

// cstringFromComponent returns a string concatenating the data of a component
// this internal function is meant to generate a predicatable string to generate
// the document's CanonicalHash
func cstringFromComponent(c Component) string {
	s := fmt.Sprintf(":%s", c.ID)

	for algo, val := range c.Hashes {
		s += fmt.Sprintf(":%s@%s", algo, val)
	}

	for t, id := range c.Identifiers {
		s += fmt.Sprintf(":%s@%s", t, id)
	}

	return s
}

// cstringFromVulnerability returns a string concatenating the vulnerability
// elements into a reproducible string that can be used to hash or index the
// vulnerability data or the statement.
func cstringFromVulnerability(v Vulnerability) string {
	cString := fmt.Sprintf(":%s:%s", v.ID, v.Name)
	list := []string{}
	for i := range v.Aliases {
		list = append(list, string(v.Aliases[i]))
	}
	sort.Strings(list)
	cString += strings.Join(list, ":")
	return cString
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
	vexDoc.ID = fmt.Sprintf("%s/public/vex-%s", DefaultNamespace, cHash)
	return vexDoc.ID, nil
}

// DateFromEnv returns a time object representing the time specified in the
// `SOURCE_DATE_EPOCH` environment variable, whose value can be specified as
// either UNIX seconds or as a RFC3339 value.
func DateFromEnv() (*time.Time, error) {
	// Support env var for reproducible vexing
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
			return nil, fmt.Errorf("failed to parse env var SOURCE_DATE_EPOCH: %w", err)
		}
	}
	return &t, nil
}
