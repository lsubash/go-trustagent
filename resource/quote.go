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

		if len(tpmQuoteRequest.Nonce) == 0 {
			seclog.Errorf("resource/quote:getTpmQuote() %s - The TpmQuoteRequest does not contain a nonce", message.InvalidInputProtocolViolation)
			return &endpointError{Message: "The TpmQuoteRequest does not contain a nonce", StatusCode: http.StatusBadRequest}
		}

		// ISECL-12121: strip inactive PCR Banks from the request
		if(len(tpmQuoteRequest.PcrBanks) >0) {
			for i, pcrBank := range tpmQuoteRequest.PcrBanks {
				isActive, err := tpm.IsPcrBankActive(pcrBank)
				if !isActive {
					log.Infof("resource/quote:getQuote() %s PCR bank is inactive. Dropping from quote request. %s",
						pcrBank, err.Error())
					tpmQuoteRequest.PcrBanks = append(tpmQuoteRequest.PcrBanks[:i], tpmQuoteRequest.PcrBanks[i+1:]...)
				} else if err != nil {
					log.WithError(err).Errorf("resource/quote:getQuote() Error while determining PCR bank "+
						"%s state: %s", pcrBank, err.Error())
				}
			}
		} else {
			// if PCR bank is nil in the TPM Quote request, return quote for all active PCR banks on the host
			supportedPCRBanks := []string{"SHA384", "SHA256", "SHA1"}
			for _, bank := range supportedPCRBanks {
				isActive, err := tpm.IsPcrBankActive(bank)
				if(isActive) {
					tpmQuoteRequest.PcrBanks = append(tpmQuoteRequest.PcrBanks, bank)
				} else if err != nil {
					log.WithError(err).Errorf("resource/quote:getQuote() Error while determining PCR bank "+
						"%s state: %s", bank, err.Error())
				}
			}
		}


		err = ctx.createTpmQuote(&tpmQuoteRequest)
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
