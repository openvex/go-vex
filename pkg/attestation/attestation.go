// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	cattestation "github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/openvex/go-vex/pkg/vex"
)

var _ cattestation.Statement = (*Attestation)(nil)

type Attestation struct {
	// Note that here, we are embedding the *intoto* Statement. Not to be
	// confused with the VEX Statement struct.
	//
	// Essentially our attestation is an extension of the intoto statement
	// with our custom predicate.
	*intoto.Statement

	// Predicate contains type specific metadata.
	Predicate *Predicate `json:"predicate"`
}

// Option configures an Attestation built with New or NewWithError. An
// Option may return an error if its configuration cannot be applied (for
// example, an option that resolves an image reference may fail to reach
// the registry). To avoid breaking changes, on error New() just logs and
// continues past such errors while NewWithError returns the first one.
type Option func(*buildOpts) error

// buildOpts holds the transient state accumulated by Options during
// construction. It is intentionally unexported; callers only see Options.
type buildOpts struct {
	predicate      *Predicate
	subjects       []*intoto.ResourceDescriptor
	importProducts bool
	resolver       ImageDigestResolver
}

// WithPredicate builds a Predicate from doc and sets it on the attestation.
// If doc is nil, a default empty VEX document is used.
func WithPredicate(doc *vex.VEX) Option {
	return func(o *buildOpts) error {
		o.predicate = NewPredicate(doc)
		return nil
	}
}

// WithSubjects appends the given resource descriptors to the attestation's
// subject list. It is repeatable: multiple WithSubjects options accumulate.
// Unlike AddSubjects, this option does not validate that each subject has a
// digest — call AddSubjects after construction if you need that check.
func WithSubjects(subs ...*intoto.ResourceDescriptor) Option {
	return func(o *buildOpts) error {
		o.subjects = append(o.subjects, subs...)
		return nil
	}
}

// WithImportProducts controls whether the products in the predicate's VEX
// document are automatically imported as attestation subjects. Defaults to
// true: pass WithImportProducts(false) to disable.
//
// See walkProductsForImport for the conversion rules.
func WithImportProducts(b bool) Option {
	return func(o *buildOpts) error {
		o.importProducts = b
		return nil
	}
}

// WithImageDigestResolver supplies the resolver used to look up the digest
// of an OCI image reference when an OCI purl in the predicate carries no
// digest of its own. Without a resolver, such purls cause the import to
// fail (or be skipped, in best-effort mode).
//
// Callers wire in their own registry client (e.g. crane, go-containerregistry,
// docker, or an in-memory map for tests) — go-vex stays free of registry
// dependencies.
func WithImageDigestResolver(r ImageDigestResolver) Option {
	return func(o *buildOpts) error {
		o.resolver = r
		return nil
	}
}

// applyOpts runs every option against a fresh buildOpts. Errors are routed
// to onError; if onError returns false, application stops at that option.
func applyOpts(opts []Option, onError func(error) bool) *buildOpts {
	bo := &buildOpts{importProducts: true}
	for _, opt := range opts {
		if err := opt(bo); err != nil {
			if !onError(err) {
				break
			}
		}
	}
	if bo.predicate == nil {
		bo.predicate = NewPredicate(nil)
	}
	return bo
}

func (bo *buildOpts) build() *Attestation {
	att := &Attestation{
		Statement: &intoto.Statement{
			Type:          intoto.StatementTypeUri,
			PredicateType: string(PredicateType),
		},
		Predicate: bo.predicate,
	}
	att.Subject = append(att.Subject, bo.subjects...)
	return att
}

// New constructs an Attestation, applying the given options. Errors from
// options or from product import are logged via slog and the offending
// step is skipped; use NewWithError for strict propagation.
func New(opts ...Option) *Attestation {
	bo := applyOpts(opts, func(err error) bool {
		slog.Warn("applying attestation option", "error", err.Error())
		return true
	})
	att := bo.build()
	if bo.importProducts {
		importProductsBestEffort(att, &att.Predicate.VEX, bo.resolver)
	}
	return att
}

// NewWithError is like New, but returns the first error encountered while
// applying options or importing products as subjects.
func NewWithError(opts ...Option) (*Attestation, error) {
	var firstErr error
	bo := applyOpts(opts, func(err error) bool {
		firstErr = err
		return false
	})
	if firstErr != nil {
		return nil, firstErr
	}
	att := bo.build()
	if bo.importProducts {
		if err := importProductsStrict(att, &att.Predicate.VEX, bo.resolver); err != nil {
			return att, err
		}
	}
	return att, nil
}

// MarshalJSON implements custom JSON marshaling for Attestation. It uses
// protojson to marshal the embedded in-toto Statement (which produces the
// correct field names like "_type" and "predicateType"), then replaces the
// predicate field with the output of the Predicate's own serialization.
func (att *Attestation) MarshalJSON() ([]byte, error) {
	// Marshal the intoto statement using protojson
	stmtJSON, err := protojson.Marshal(att.Statement)
	if err != nil {
		return nil, fmt.Errorf("marshaling intoto statement: %w", err)
	}

	// Decode the statement into a generic map so we can replace the predicate
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(stmtJSON, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshaling statement envelope: %w", err)
	}

	// Replace the predicate with the output from our custom Predicate type
	if att.Predicate != nil {
		data := att.Predicate.GetData()
		if data != nil {
			envelope["predicate"] = json.RawMessage(data)
		}
	}

	return json.Marshal(envelope)
}

// ToJSON writes the attestation as JSON to the io.Writer w
func (att *Attestation) ToJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(att); err != nil {
		return fmt.Errorf("encoding attestation: %w", err)
	}

	return nil
}

// AddSubjects adds a list of intoto subjects to the attestation
func (att *Attestation) AddSubjects(subs []*intoto.ResourceDescriptor) error {
	for _, s := range subs {
		if len(s.GetDigest()) == 0 {
			return fmt.Errorf("subject %s has no digests", s.GetName())
		}
	}
	att.Subject = append(att.Subject, subs...)
	return nil
}

func (att *Attestation) GetSubjects() []cattestation.Subject {
	ret := []cattestation.Subject{}
	if att.Statement == nil {
		return ret
	}
	for _, s := range att.GetSubject() {
		ret = append(ret, s)
	}
	return ret
}

func (att *Attestation) GetPredicate() cattestation.Predicate {
	return att.Predicate
}

func (att *Attestation) GetPredicateType() cattestation.PredicateType {
	if att.Predicate != nil {
		return att.Predicate.GetType()
	}
	return cattestation.PredicateType(att.Statement.GetPredicateType())
}

func (att *Attestation) GetType() string {
	return intoto.StatementTypeUri
}

func (att *Attestation) GetVerification() cattestation.Verification {
	if att.Predicate == nil {
		return nil
	}
	return att.Predicate.GetVerification()
}
