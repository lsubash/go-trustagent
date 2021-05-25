/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"

	"encoding/json"
	"intel/isecl/go-trust-agent/v4/common"
	"intel/isecl/go-trust-agent/v4/constants"
	"net/http"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
)

func getPlatformInfo(requestHandler common.RequestHandler) endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/host:getPlatformInfo() Entering")
		defer log.Trace("resource/host:getPlatformInfo() Leaving")

		log.Debugf("resource/host:getPlatformInfo() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type when calling /host
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("resource/host:getPlatformInfo() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		hostInfo, err := requestHandler.GetHostInfo()
		if err != nil {
			log.Errorf("resource/host:getPlatformInfo() %s - There was an error reading %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
			return &common.EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		hostInfoJSON, err := json.Marshal(hostInfo)
		if err != nil {
			log.Errorf("resource/host:getPlatformInfo() %s - There was an error marshaling host-info %s", message.AppRuntimeErr, constants.PlatformInfoFilePath)
			return &common.EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.Header().Set("Content-Type", "application/json")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(hostInfoJSON).WriteTo(httpWriter)
		return nil
	}
}
