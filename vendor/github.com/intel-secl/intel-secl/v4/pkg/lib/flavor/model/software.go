/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import (
	"github.com/intel-secl/intel-secl/v4/pkg/model/ta"
)

/**
 *
 * @author mullas
 */

// Software consists of integrity measurements of Software/OS related resources
type Software struct {
	Measurements   map[string]model.FlavorMeasurement `json:"measurements,omitempty"`
	CumulativeHash string                             `json:"cumulative_hash,omitempty"`
}
