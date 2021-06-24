/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/lib/tpmprovider/v4"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	"github.com/pkg/errors"
)

type DefineTagIndex struct {
	tpmFactory     tpmprovider.TpmFactory
	ownerSecretKey **string
	assetTagSecret *string // out variable that is saved to cfg.TPM.TagSecretKey
}

func (task *DefineTagIndex) Run(c setup.Context) error {

	// by default, define and store an empty 'tag' that is stored in nvram.
	newAssetTag := make([]byte, constants.TagIndexSize)

	fmt.Println("Running setup task: deploy-asset-tag")

	if task.ownerSecretKey == nil || *task.ownerSecretKey == nil {
		return errors.New("The owner-secret was not provided.")
	}

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	owned, err := tpm.IsOwnedWithAuth(**task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Runtime error while verifying the owner-secret")
	}

	if !owned {
		return errors.New("The owner-secret provided cannot access the TPM.")
	}

	// if the tag-secret is not defined, create one
	if *task.assetTagSecret == "" {
		*task.assetTagSecret, err = crypt.GetHexRandomString(20)
		if err != nil {
			return errors.Wrap(err, "Error while generating a tag-secret")
		}
	}

	// check if an asset tag does not exists...
	nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return errors.Wrap(err, "Error checking if the tag index exists in nvram")
	}

	// If it exists, carry it forward so that trust-reports are still trusted...
	if nvExists {

		// read the existing asset tag
		existingAssetTag, err := tpm.NvRead(**task.ownerSecretKey, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			return errors.Wrap(err, "Failed to read existing asset tag")
		}

		// 48 is number of bytes of legacy tag (sha384)
		if existingAssetTag == nil || len(existingAssetTag) != constants.TagIndexSize {
			// we don't know what this is so just delete it.
			log.Warn("The existing asset tag is invalid will not be migrated")
		} else {
			log.Info("Migrating asset tag")
			copy(newAssetTag, existingAssetTag)
		}

		// delete old nvram index so that it can be recreated
		err = tpm.NvRelease(**task.ownerSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			return errors.Wrap(err, "Error deleting the previous tag index from nvram")
		}
	}

	// create an index for the tag
	err = tpm.NvDefine(**task.ownerSecretKey, *task.assetTagSecret, tpmprovider.NV_IDX_ASSET_TAG, constants.TagIndexSize)
	if err != nil {
		return errors.Wrap(err, "Error defining the tag index in nvram")
	}

	// Either put back the existing asset tag or basically do a "memset" on the index
	// so that common.RequestHandler can determine if the tag is empty or defined.
	err = tpm.NvWrite(*task.assetTagSecret, tpmprovider.NV_IDX_ASSET_TAG, tpmprovider.NV_IDX_ASSET_TAG, newAssetTag)
	if err != nil {
		return errors.Wrap(err, "Error writing tag to nvram")
	}

	return nil
}

func (task *DefineTagIndex) Validate(c setup.Context) error {

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	// check if an asset tag does not exists...
	nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return errors.Wrap(err, "Validation error: NvIndexExists failed")
	}

	if !nvExists {
		return errors.New("The asset tag nvram index was not created")
	}

	log.Debug("'define-tag-index' completed successfully.")
	return nil
}
