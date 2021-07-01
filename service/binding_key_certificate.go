/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"bytes"
	"intel/isecl/go-trust-agent/v4/common"
	"net/http"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
)

// Returns the WLA provisioned binding key certificate from /etc/workload-agent/bindingkey.pem
//
// Ex. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/binding-key-certificate -k --noproxy "*"
func getBindingKeyCertificate(requestHandler common.RequestHandler) endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/binding_key_certificate:getBindingKeyCertificate() Entering")
		defer log.Trace("resource/binding_key_certificate:getBindingKeyCertificate() Leaving")

		log.Debugf("resource/binding_key_certificate:getBindingKeyCertificate() Request: %s", httpRequest.URL.Path)

		// HVS does not provide a content-type, exlude other values
		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "" {
			log.Errorf("resource/binding_key_certificate:getBindingKeyCertificate() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		bindingKeyBytes, err := requestHandler.GetBindingCertificateDerBytes()
		if err != nil {
			log.WithError(err).Errorf("resource/binding_key_certificate:getBindingKeyCertificate() %s - Error while getting binding key", message.AppRuntimeErr)
			return err
		}

		httpWriter.Header().Set("Content-Type", "application/x-pem-file")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(bindingKeyBytes).WriteTo(httpWriter)
		return nil
	}
}
