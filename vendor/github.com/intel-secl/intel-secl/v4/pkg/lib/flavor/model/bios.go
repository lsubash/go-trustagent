/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

/**
 *
 * @author mullas
 */

// Bios holds details of the Bios vendor firmware information
type Bios struct {
	BiosName    string `json:"bios_name"`
	BiosVersion string `json:"bios_version"`
}
