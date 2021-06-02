/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"intel/isecl/go-trust-agent/v4/common"
	"io/ioutil"
	"net/http"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
)

//
// Provided the TagWriteRequest from, delete any existing tags, define/write
// tag to the TPM's nvram.  The receiving side of this equation is in 'quote.go'
// where the asset tag is used to hash the nonce and is also appended to the
// quote xml.
//
func setAssetTag(requestHandler common.RequestHandler) endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/asset_tag:setAssetTag() Entering")
		defer log.Trace("resource/asset_tag:setAssetTag() Leaving")

		log.Debugf("resource/asset_tag:setAssetTag() Request: %s", httpRequest.URL.Path)

		var tagWriteRequest taModel.TagWriteRequest

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/json" {
			log.Errorf("resource/asset_tag:setAssetTag( %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.WithError(err).Errorf("resource/asset_tag:setAssetTag() %s - Error reading request body for request: %s", message.AppRuntimeErr, httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error parsing request", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&tagWriteRequest)
		if err != nil {
			secLog.WithError(err).Errorf("resource/asset_tag:setAssetTag() %s - Error marshaling json data: %s for request: %s", message.InvalidInputBadParam, string(data), httpRequest.URL.Path)
			return &common.EndpointError{Message: "Error processing request", StatusCode: http.StatusBadRequest}
		}

		err = requestHandler.DeployAssetTag(&tagWriteRequest)
		if err != nil {
			log.WithError(err).Errorf("resource/asset_tag:setAssetTag() %s - Error while deploying asset tag", message.AppRuntimeErr)
			return err
		}
		httpWriter.WriteHeader(http.StatusOK)
		return nil
	}
}
