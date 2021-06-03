/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/json"
	"intel/isecl/go-trust-agent/v4/constants"
	"io/ioutil"
	"os"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
)

// GetHostInfo Assuming that the /opt/trustagent/var/system-info/platform-info file has been created
// during startup, this function reads the contents of the json file and returns the corresponding
// HostInfo structure.
func (handler *requestHandlerImpl) GetHostInfo() (*taModel.HostInfo, error) {
	var hostInfo taModel.HostInfo

	if _, err := os.Stat(constants.PlatformInfoFilePath); os.IsNotExist(err) {
		log.WithError(err).Errorf("common/hostinfo:GetHostInfo() %s - %s does not exist", message.AppRuntimeErr, constants.PlatformInfoFilePath)
		return nil, err
	}

	jsonData, err := ioutil.ReadFile(constants.PlatformInfoFilePath)
	if err != nil {
		log.Errorf("common/hostinfo:GetHostInfo() %s - There was an error reading %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonData, &hostInfo)
	if err != nil {
		return nil, err
	}

	return &hostInfo, nil
}
