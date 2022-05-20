/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

// Integrity contains information pertaining to the Integrity policy of the image
type Integrity struct {
	NotaryURL string `json:"notary_url,omitempty"`
}
