/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/xml"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"intel/isecl/go-trust-agent/v4/constants"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/validation"
	flavorConsts "github.com/intel-secl/intel-secl/v4/pkg/lib/flavor/constants"
)

func (handler *requestHandlerImpl) DeploySoftwareManifest(manifest *taModel.Manifest) error {

	manifestXml, err := xml.Marshal(manifest)
	if err != nil {
		secLog.Errorf("%s common/deploy_manifest:DeploySoftwareManifest() Failed to marshal manifest %s", message.InvalidInputBadParam, err.Error())
		return &EndpointError{Message: "Error: Failed to marshal manifest", StatusCode: http.StatusBadRequest}
	}

	err = validation.ValidateUUIDv4(manifest.Uuid)
	if err != nil {
		secLog.Errorf("%s common/deploy_manifest:DeploySoftwareManifest() Invalid uuid %s", message.InvalidInputBadParam, err.Error())
		return &EndpointError{Message: "Error: Invalid uuid", StatusCode: http.StatusBadRequest}
	}

	if len(manifest.Label) == 0 {
		log.Error("The manifest did not contain a label")
		return &EndpointError{Message: "Error: The manifest did not contain a label", StatusCode: http.StatusBadRequest}
	}

	var manifestlabels []string
	manifestlabels = append(manifestlabels, manifest.Label)
	err = validation.ValidateStrings(manifestlabels)
	if err != nil {
		secLog.Errorf("%s common/deploy_manifest:DeploySoftwareManifest() Invalid manifest labels %s", message.InvalidInputBadParam, err.Error())
		return &EndpointError{Message: "Error: Invalid manifest labels", StatusCode: http.StatusBadRequest}
	}

	if strings.Contains(manifest.Label, flavorConsts.DefaultSoftwareFlavorPrefix) ||
		strings.Contains(manifest.Label, flavorConsts.DefaultWorkloadFlavorPrefix) {
		log.Errorf("common/deploy_manifest:DeploySoftwareManifest() Default flavor's manifest (%s) is part of installation, no need to deploy default flavor's manifest", manifest.Label)
		return &EndpointError{Message: " Default flavor's manifest (%s) is part of installation", StatusCode: http.StatusBadRequest}
	}

	// establish the name of the manifest file and write the file
	manifestFile := constants.VarDir + "manifest_" + manifest.Uuid + ".xml"
	err = ioutil.WriteFile(manifestFile, manifestXml, 0600)
	if err != nil {
		log.Errorf("common/deploy_manifest:DeploySoftwareManifest() Could not write manifest: %s", err)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	return nil
}
