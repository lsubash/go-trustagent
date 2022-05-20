/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package asset_tag

import hc "github.com/intel-secl/intel-secl/v4/pkg/lib/host-connector"

// AssetTag interface is used to create and deploy an asset tag certificate on a host
type AssetTag interface {
	CreateAssetTag(TagCertConfig) ([]byte, error)
	DeployAssetTag(hc.HostConnector, string, string) error
}

// NewAssetTag returns an instance to the AssetTag interface
func NewAssetTag() AssetTag {
	return &atag{}
}
