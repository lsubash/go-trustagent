/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

/**
 *
 * @author mullas
 */

// HardwareFeatureDetails describes the presence/state of the platform features on the current system
type HardwareFeatureDetails struct {
	Enabled bool              `json:"enabled"`
	Meta    map[string]string `json:"meta"`
}
