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

	tagSecretKey, err := crypt.GetHexRandomString(20)
	if err != nil {
		return errors.Wrap(err, "Error while generating a tag-secret")
	}

	// check if an asset tag does not exists...
	nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return errors.Wrap(err, "Error checking if the tag index exists in nvram")
	}

	// if it exists, delete it so that it can be recreated
	if nvExists {
		err = tpm.NvRelease(**task.ownerSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			return errors.Wrap(err, "Error deleting the previous tag index from nvram")
		}
	}

	// create an index for the tag
	err = tpm.NvDefine(**task.ownerSecretKey, tagSecretKey, tpmprovider.NV_IDX_ASSET_TAG, constants.TagIndexSize)
	if err != nil {
		return errors.Wrap(err, "Error defining the tag index in nvram")
	}

	// basically do a "memset" on the tag index...
	emptyTag := make([]byte, constants.TagIndexSize)
	err = tpm.NvWrite(tagSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tpmprovider.NV_IDX_ASSET_TAG, emptyTag)
	if err != nil {
		return errors.Wrap(err, "Error writing empty tag to nvram")
	}

	*task.assetTagSecret = tagSecretKey

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
