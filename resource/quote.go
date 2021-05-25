/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"encoding/xml"

	"intel/isecl/go-trust-agent/v4/common"
	"io/ioutil"
	"net/http"


	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
)

func getTpmQuote(requestHandler common.RequestHandler) endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/quote:getTpmQuote() Entering")
		defer log.Trace("resource/quote:getTpmQuote() Leaving")

		log.Debugf("resource/quote:getTpmQuote() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/json" {
			log.Errorf("resource/quote:getTpmQuote() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		var tpmQuoteRequest taModel.TpmQuoteRequest

		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("resource/quote:getTpmQuote() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error reading request body", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&tpmQuoteRequest)
		if err != nil {
			seclog.WithError(err).Errorf("resource/quote:getTpmQuote() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
			return &common.EndpointError{Message: "Error marshaling json data", StatusCode: http.StatusBadRequest}

		}

		tpmQuoteResponse, err := requestHandler.GetTpmQuote(&tpmQuoteRequest)
		if err != nil {
			log.WithError(err).Errorf("resource/quote:getTpmQuote() %s - There was an error collecting the tpm quote", message.AppRuntimeErr)
			return &common.EndpointError{Message: "There was an error collecting the tpm quote", StatusCode: http.StatusInternalServerError}
		}

		xmlOutput, err := xml.MarshalIndent(tpmQuoteResponse, "  ", "    ")
		if err != nil {
			log.WithError(err).Errorf("resource/quote:getTpmQuote() %s - There was an error serializing the tpm quote", message.AppRuntimeErr)
			return &common.EndpointError{Message: "There was an error serializing the tpm quote", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.Header().Set("Content-Type", "application/xml")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(xmlOutput).WriteTo(httpWriter)
		return nil
	}
}
