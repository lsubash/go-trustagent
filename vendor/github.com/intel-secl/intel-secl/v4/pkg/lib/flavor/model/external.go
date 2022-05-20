/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

/**
 *
 * @author mullas
 */

// External is a component of flavor that encloses the AssetTag cert
type External struct {
	AssetTag AssetTag `json:"asset_tag,omitempty"`
}

// AssetTag is used to hold the Asset Tag certificate provisioned by VS for the host
type AssetTag struct {
	TagCertificate X509AttributeCertificate `json:"tag_certificate"`
}
