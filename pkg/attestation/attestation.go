/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"encoding/json"
	"fmt"
	"io"

	intoto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/openvex/go-vex/pkg/vex"
)

type Attestation struct {
	intoto.StatementHeader
	// Predicate contains type specific metadata.
	Predicate vex.VEX `json:"predicate"`
}

func New() *Attestation {
	return &Attestation{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: vex.TypeURI,
			Subject:       []intoto.Subject{},
		},
		Predicate: vex.New(),
	}
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
func (att *Attestation) AddSubjects(subs []intoto.Subject) error {
	for _, s := range subs {
		if len(s.Digest) == 0 {
			return fmt.Errorf("subject %s has no digests", s.Name)
		}
	}
	att.Subject = append(att.Subject, subs...)
	return nil
}
