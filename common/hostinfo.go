/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"github.com/pkg/errors"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/go-trust-agent/v4/util"
)

// GetHostInfo Assuming that the /opt/trustagent/var/system-info/platform-info file has been created
// during startup, this function reads the contents of the json file and returns the corresponding
// HostInfo structure.
func (handler *requestHandlerImpl) GetHostInfo() (*taModel.HostInfo, error) {
	var hostInfo *taModel.HostInfo

	hostInfo, err := util.ReadHostInfo()
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading host-info file %s", constants.PlatformInfoFilePath)
	}

	return hostInfo, nil
}
