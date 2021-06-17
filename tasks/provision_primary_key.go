/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/lib/tpmprovider/v4"

	"github.com/pkg/errors"
)

type ProvisionPrimaryKey struct {
	tpmFactory     tpmprovider.TpmFactory
	ownerSecretKey **string
}

// This task is used to persist a primary public key at handle TPM_HANDLE_PRIMARY
// to be used by WLA for signing/binding keys.
func (task *ProvisionPrimaryKey) Run(c setup.Context) error {
	log.Trace("tasks/provision_primary_key:Run() Entering")
	defer log.Trace("tasks/provision_primary_key:Run() Leaving")
	fmt.Println("Running setup task: provision-primary-key")

	if task.ownerSecretKey == nil || *task.ownerSecretKey == nil {
		errorMessage := `The 'provision-primary-key' task requires the owner-secret.  If you wish to generate
		a new owner-secret (i.e., with take-ownership), 'provision-primary-key' must be 
		run at the same time using 'tagent setup' or 'tagent setup provsion-attestation'.`
		return errors.New(errorMessage)
	}

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		return errors.Wrap(err, "Error while checking existence of tpm public key")
	}

	if !exists {
		err = tpm.CreatePrimaryHandle(**task.ownerSecretKey, tpmprovider.TPM_HANDLE_PRIMARY)
		if err != nil {
			return errors.Wrap(err, "Error while creating the primary handle in the TPM")
		}
	}

	return nil
}

func (task *ProvisionPrimaryKey) Validate(c setup.Context) error {
	log.Trace("tasks/provision_primary_key:Validate() Entering")
	defer log.Trace("tasks/provision_primary_key:Validate() Leaving")
	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		return errors.Wrap(err, "Error while checking existence of tpm public key")
	}

	if !exists {
		return errors.Wrapf(err, "The primary key at handle %x was not created", tpmprovider.TPM_HANDLE_PRIMARY)
	}

	// assume valid if error did not occur during 'Run'
	log.Debug("tasks/provision_primary_key:Validate() Provisioning the primary key was successful.")
	return nil
}
