/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"
	"github.com/intel-secl/intel-secl/v4/pkg/clients/vmware"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
	"net/url"
)

type VmwareConnectorFactory struct {
}

func (vcf *VmwareConnectorFactory) GetHostConnector(vc types.VendorConnector, aasApiUrl string,
	trustedCaCerts []x509.Certificate) (HostConnector, error) {
	log.Trace("vmware_host_connector_factory:GetHostConnector() Entering")
	defer log.Trace("vmware_host_connector_factory:GetHostConnector() Leaving")

	parsedURL, err := url.Parse(vc.Url)
	if err != nil {
		return nil, errors.Wrap(err, "vmware_host_connector_factory:GetHostConnector() Invalid vcenter URL provided")
	}

	vmwareClient, err := vmware.NewVMwareClient(parsedURL, vc.Configuration.Username, vc.Configuration.Password,
		vc.Configuration.Hostname, trustedCaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating vmware client")
	}
	return &VmwareConnector{vmwareClient}, nil
}
