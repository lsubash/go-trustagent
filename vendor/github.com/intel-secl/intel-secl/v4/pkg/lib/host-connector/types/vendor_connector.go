/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import "github.com/intel-secl/intel-secl/v4/pkg/lib/host-connector/constants"

type VendorConnector struct {
	Vendor        constants.Vendor
	Url           string
	Configuration struct {
		Hostname string
		Username string
		Password string
	}
}
