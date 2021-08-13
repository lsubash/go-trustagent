package util

import (
	"encoding/json"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"github.com/pkg/errors"
	"intel/isecl/go-trust-agent/v4/constants"
	"io/ioutil"
	"os"
)

func ReadHostInfo() (*taModel.HostInfo, error) {
	var hostInfo taModel.HostInfo
	if _, err := os.Stat(constants.PlatformInfoFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - %s does not exist", message.AppRuntimeErr, constants.PlatformInfoFilePath)
	}

	jsonData, err := ioutil.ReadFile(constants.PlatformInfoFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - There was an error reading %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
	}

	err = json.Unmarshal(jsonData, &hostInfo)
	if err != nil {
		return nil, errors.Wrapf(err, "util/ReadHostInfo() %s - There was an error unmarshalling the hostInfo", message.AppRuntimeErr)
	}
	return &hostInfo, nil
}
