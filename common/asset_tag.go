/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/validation"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"intel/isecl/lib/tpmprovider/v4"
	"net/http"
)

func (handler *requestHandlerImpl) DeployAssetTag(tagWriteRequest *taModel.TagWriteRequest) error {
	//tpmQuoteResponse, err := requestHandler.GetTpmQuote(&tpmQuoteRequest)
	tpmSecretKey := handler.cfg.Tpm.OwnerSecretKey
	err := validation.ValidateHardwareUUID(tagWriteRequest.HardwareUUID)
	if err != nil {
		log.Errorf("common/asset_tag:DeployAssetTag( %s - Invalid hardware_uuid '%s'", message.InvalidInputBadParam, tagWriteRequest.HardwareUUID)
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

	// check if an asset tag already exists and delete it if needed
	nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		log.WithError(err).Errorf("common/asset_tag:DeployAssetTag() %s - Error checking if asset tag exists", message.AppRuntimeErr)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	if nvExists {
		err = tpm.NvRelease(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			log.WithError(err).Errorf("common/asset_tag:DeployAssetTag() %s - Could not release asset tag nvram", message.AppRuntimeErr)
			return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}
	}

	// create an index for the data
	err = tpm.NvDefine(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, uint16(len(tagWriteRequest.Tag)))
	if err != nil {
		log.Errorf("common/asset_tag:DeployAssetTag() %s - Could not define tag nvram", message.AppRuntimeErr)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	// write the data
	err = tpm.NvWrite(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tagWriteRequest.Tag)
	if err != nil {
		log.WithError(err).Errorf("common/asset_tag:DeployAssetTag() %s - Error writing asset tag", message.AppRuntimeErr)
		return &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	return nil
}
