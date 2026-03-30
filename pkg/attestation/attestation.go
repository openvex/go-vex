/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"encoding/json"
	"fmt"
	"io"

	cattestation "github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
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

func New() *Attestation {
	return &Attestation{
		Statement: &intoto.Statement{
			Type:          intoto.StatementTypeUri,
			PredicateType: string(PredicateType),
		},
		Predicate: NewPredicate(nil),
	}
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
