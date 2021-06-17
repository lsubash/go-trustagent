/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"intel/isecl/go-trust-agent/v4/common"
	"intel/isecl/go-trust-agent/v4/constants"
	"net/http"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
)

func getAik(requestHandler common.RequestHandler) endpointHandler {

	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/aik:getAik() Entering")
		defer log.Trace("resource/aik:getAik() Leaving")

		log.Debugf("resource/aik:getAik() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type to /aik, so only allow the empty string...
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("resource/aik:getAik() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		aikDer, err := requestHandler.GetAikDerBytes()
		if err != nil {
			log.WithError(err).Errorf("resource/aik:getAik() %s - There was an error reading %s", message.AppRuntimeErr, constants.AikCert)
			return &common.EndpointError{Message: "Unable to fetch AIK certificate", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(aikDer).WriteTo(httpWriter)
		return nil
	}
}
