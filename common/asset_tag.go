/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"intel/isecl/lib/tpmprovider/v4"
	"net/http"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/validation"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
)

func (handler *requestHandlerImpl) DeployAssetTag(tagWriteRequest *taModel.TagWriteRequest) error {

	err := validation.ValidateHardwareUUID(tagWriteRequest.HardwareUUID)
	if err != nil {
		log.WithError(err).Errorf("common/asset_tag:DeployAssetTag( %s - Invalid hardware_uuid '%s'", message.InvalidInputBadParam, tagWriteRequest.HardwareUUID)
		return &EndpointError{Message: "Invalid hardware_uuid", StatusCode: http.StatusBadRequest}
	}

	tpmFactory, err := tpmprovider.NewTpmFactory()
	if err != nil {
		return err
	}

	tpm, err := tpmFactory.NewTpmProvider()
	if err != nil {
		log.WithError(err).Errorf("common/asset_tag:DeployAssetTag() %s - Error creating tpm provider", message.AppRuntimeErr)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	defer tpm.Close()

	// check if an asset tag does not exist, it should have been created during provisioning
	nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		log.WithError(err).Errorf("common/asset_tag:DeployAssetTag() %s - Error checking if asset tag exists", message.AppRuntimeErr)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	if !nvExists {
		log.WithError(err).Errorf("resource/asset_tag:setAssetTag() %s - The asset tag index does not exist", message.AppRuntimeErr)
		return &EndpointError{Message: "The asset tag index does not exist", StatusCode: http.StatusInternalServerError}
	}

	// write the tag
	err = tpm.NvWrite(handler.cfg.Tpm.TagSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tpmprovider.NV_IDX_ASSET_TAG, tagWriteRequest.Tag)
	if err != nil {
		log.WithError(err).Errorf("common/asset_tag:DeployAssetTag() %s - Error writing asset tag", message.AppRuntimeErr)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	return nil
}
