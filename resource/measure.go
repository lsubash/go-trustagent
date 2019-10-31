/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
package resource

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
//	"strings"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
)

const WML_LOG_FILE = constants.LogDir + "wml.log"

func getApplicationMeasurement(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	log.Debugf("Request: %s", httpRequest.URL.Path)

	// receive a manifest from hvs in the request body
	manifestXml, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Application Measurement: Error reading manifest xml: %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	// make sure the xml is well formed, all other validation will be 
	// peformed by 'measure' cmd line below
	err = xml.Unmarshal(manifestXml, new(interface{}))
	if err != nil {
		log.Errorf("Application Measurement: Invalid xml format: %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	// this should probably be done in wml --> if the wml log file is not yet created,
	// 'measure' will fail.  for now, create the file before calling 'measure'.
	if _, err := os.Stat(WML_LOG_FILE); os.IsNotExist(err) {
		os.OpenFile(WML_LOG_FILE, os.O_RDONLY|os.O_CREATE, 0600)
	}

	// call /opt/tbootxml/bin/meaure and return the xml from stdout
	// 'measure <manifestxml> /'
	cmd := exec.Command(constants.TBootXmMeasurePath, string(manifestXml), "/")
	cmd.Env = append(os.Environ(), "WML_LOG_FILE=" + WML_LOG_FILE,)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("Error getting measure output: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = cmd.Start()
	if err != nil {
		log.Errorf("Error starting measure: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	measureBytes, _ := ioutil.ReadAll(stdout)
	err = cmd.Wait()
	if err != nil {
		log.Errorf("Measure failed: '%s'.  Stdout: %s", err, string(measureBytes))
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	// make sure we got valid xml from measure
	err = xml.Unmarshal(measureBytes, new(interface{}))
	if err != nil {
		log.Errorf("Invalid measurement xml: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
	_, _ = bytes.NewBuffer(measureBytes).WriteTo(httpWriter)
	return
}