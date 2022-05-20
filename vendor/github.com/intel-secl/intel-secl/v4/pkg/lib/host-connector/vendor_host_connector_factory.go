/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/host-connector/types"
)

type VendorHostConnectorFactory interface {
	GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl string, trustedCaCerts []x509.Certificate) (HostConnector, error)
}
