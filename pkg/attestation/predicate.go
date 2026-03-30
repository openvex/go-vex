// Copyright 2026 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"bytes"
	"errors"
	"fmt"

	cattestation "github.com/carabiner-dev/attestation"

	"github.com/openvex/go-vex/pkg/vex"
)

var PredicateType cattestation.PredicateType = "https://openvex.dev/ns/v0.2.0"

var _ cattestation.Predicate = (*Predicate)(nil)

type Predicate struct {
	vex.VEX
	verification cattestation.Verification `json:"-"`
	origin       cattestation.Subject
}

func NewPredicate(doc *vex.VEX) *Predicate {
	if doc == nil {
		d := vex.New()
		doc = &d
	}

	return &Predicate{
		VEX: *doc,
	}
}

func (p *Predicate) GetType() cattestation.PredicateType {
	return cattestation.PredicateType(p.Context)
}

func (p *Predicate) SetType(t cattestation.PredicateType) error {
	if p.Context == "" {
		return errors.New("vex document has empty context")
	}
	if p.Context != string(t) {
		return fmt.Errorf("unable to set predicate type, document is %s", p.Context)
	}
	return nil
}

func (p *Predicate) GetParsed() any {
	return p.VEX
}

func (p *Predicate) GetData() []byte {
	var b bytes.Buffer
	if err := p.ToJSON(&b); err != nil {
		return nil
	}

	return b.Bytes()
}

func (p *Predicate) GetVerification() cattestation.Verification {
	return p.verification
}

func (p *Predicate) GetOrigin() cattestation.Subject {
	return p.origin
}

func (p *Predicate) SetOrigin(org cattestation.Subject) {
	p.origin = org
}

func (p *Predicate) SetVerification(v cattestation.Verification) {
	p.verification = v
}
