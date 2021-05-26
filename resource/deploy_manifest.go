/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/xml"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"intel/isecl/go-trust-agent/v4/common"
	"io/ioutil"
	"net/http"
)

// Writes the manifest xml received to /opt/trustagent/var/manifest_{UUID}.xml.
func deployManifest(requestHandler common.RequestHandler) endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/deploy_manifest:deployManifest() Entering")
		defer log.Trace("resource/deploy_manifest:deployManifest() Leaving")

		log.Debugf("resource/deploy_manifest:deployManifest() Request: %s", httpRequest.URL.Path)

		contentType := httpRequest.Header.Get("Content-Type")
		if contentType != "application/xml" {
			log.Errorf("resource/deploy_manifest:deployManifest() %s - Invalid content-type '%s'", message.InvalidInputBadParam, contentType)
			return &common.EndpointError{Message: "Invalid content-type", StatusCode: http.StatusBadRequest}
		}

		// receive a manifest from hvs in the request body
		manifestXml, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("resource/deploy_manifest:deployManifest() Error reading manifest xml: %s", err)
			return &common.EndpointError{Message: "Error reading manifest xml", StatusCode: http.StatusBadRequest}
		}

		// make sure the xml is well formed
		manifest := taModel.Manifest{}
		err = xml.Unmarshal(manifestXml, &manifest)
		if err != nil {
			log.Errorf("resource/deploy_manifest:deployManifest() Invalid xml format: %s", err)
			return &common.EndpointError{Message: "Error: Invalid xml format", StatusCode: http.StatusBadRequest}
		}

		err = requestHandler.DeploySoftwareManifest(&manifest)
		if err != nil {
			log.WithError(err).Errorf("resource/deploy_manifest:deployManifest() %s - Error while deploying manifest", message.AppRuntimeErr)
			return err
		}

		httpWriter.WriteHeader(http.StatusOK)
		return nil
	}
}
