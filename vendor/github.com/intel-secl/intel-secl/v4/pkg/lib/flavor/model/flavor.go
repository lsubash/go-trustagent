/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"crypto/sha512"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// Flavor is a standardized set of expectations that determines what platform
// measurements will be considered “trusted.”
type Flavor struct {
	// Meta section is mandatory for all Flavor types
	Meta Meta  `json:"meta"`
	Bios *Bios `json:"bios,omitempty"`
	// Hardware section is unique to Platform Flavor type
	Hardware *Hardware          `json:"hardware,omitempty"`
	Pcrs     []types.FlavorPcrs `json:"pcrs,omitempty"`
	// External section is unique to AssetTag Flavor type
	External *External `json:"external,omitempty"`
	Software *Software `json:"software,omitempty"`
}

// NewFlavor returns a new instance of Flavor
func NewFlavor(meta *Meta, bios *Bios, hardware *Hardware, pcrs []types.FlavorPcrs, external *External, software *Software) *Flavor {
	// Since maps are hard to marshal as JSON, let's try to convert the DigestAlgorithm and PcrIndex to strings
	return &Flavor{
		Meta:     *meta,
		Bios:     bios,
		Hardware: hardware,
		Pcrs:     pcrs,
		External: external,
		Software: software,
	}
}

// GetFlavorDigest Calculates the SHA384 hash of the Flavor's json data for use when
// signing/verifying signed flavors.
func (flavor *Flavor) getFlavorDigest() ([]byte, error) {
	// account for a differences in properties set at runtime
	tempFlavor := *flavor
	tempFlavor.Meta.ID = uuid.Nil

	flavorJSON, err := json.Marshal(tempFlavor)
	if err != nil {
		return nil, errors.Wrap(err, "An error occurred attempting to convert the flavor to json")
	}

	if flavorJSON == nil || len(flavorJSON) == 0 {
		return nil, errors.New("The flavor json was not provided")
	}

	hashEntity := sha512.New384()
	_, err = hashEntity.Write(flavorJSON)
	if err != nil {
		return nil, errors.Wrap(err, "Error writing flavor hash")
	}
	return hashEntity.Sum(nil), nil
}
