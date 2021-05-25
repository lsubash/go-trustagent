/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/xml"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"intel/isecl/go-trust-agent/v4/constants"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
)

const WML_LOG_FILE = constants.LogDir + "wml.log"

func (handler *requestHandlerImpl) GetApplicationMeasurement(manifest *taModel.Manifest) (*taModel.Measurement, error) {

	manifestXml, err := xml.Marshal(manifest)
	if err != nil {
		secLog.Errorf("%s common/measure:GetApplicationMeasurement()  Failed to marshal manifest %s", message.InvalidInputBadParam, err.Error())
		return nil, &EndpointError{Message: "Error: Failed to marshal manifest", StatusCode: http.StatusBadRequest}
	}

	// this should probably be done in wml --> if the wml log file is not yet created,
	// 'measure' will fail.  for now, create the file before calling 'measure'.
	if _, err = os.Stat(WML_LOG_FILE); os.IsNotExist(err) {
		_, err = os.OpenFile(WML_LOG_FILE, os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() - Unable to open file")
			return nil, &EndpointError{Message: "Error: Unable to open log file", StatusCode: http.StatusInternalServerError}
		}
	}

	// make sure 'measure' is not a symbolic link before executing it
	measureExecutable, err := os.Lstat(constants.TBootXmMeasurePath)
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() - Unable to stat tboot path")
		return nil, &EndpointError{Message: "Error: Unable to stat tboot path", StatusCode: http.StatusInternalServerError}
	}
	if measureExecutable.Mode()&os.ModeSymlink == os.ModeSymlink {
		secLog.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - 'measure' is a symbolic link", message.InvalidInputBadParam)
		return nil, &EndpointError{Message: "Error: Invalid 'measure' file", StatusCode: http.StatusInternalServerError}
	}

	// call /opt/tbootxml/bin/measure and return the xml from stdout
	// 'measure <manifestxml> /'
	cmd := exec.Command(constants.TBootXmMeasurePath, string(manifestXml), "/")
	cmd.Env = append(os.Environ(), "WML_LOG_FILE="+WML_LOG_FILE)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - Error getting measure output", message.AppRuntimeErr)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	err = cmd.Start()
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - Failed to run: %s", message.AppRuntimeErr, constants.TBootXmMeasurePath)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

	}

	measureBytes, _ := ioutil.ReadAll(stdout)
	err = cmd.Wait()
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - %s returned '%s'", message.AppRuntimeErr, constants.TBootXmMeasurePath, string(measureBytes))
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	var measurement taModel.Measurement
	// make sure we got valid xml from measure
	err = xml.Unmarshal(measureBytes, &measurement)
	if err != nil {
		secLog.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - Invalid measurement xml : %s", message.AppRuntimeErr, string(measureBytes))
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	return &measurement, nil
}
