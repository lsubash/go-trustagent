/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/lib/tpmprovider/v4"
)

type TakeOwnership struct {
	tpmFactory     tpmprovider.TpmFactory
	ownerSecretKey **string // this is an 'out' variable that can be set by the task
}

func (task *TakeOwnership) Run(c setup.Context) error {
	log.Trace("tasks/take_ownership:Run() Entering")
	defer log.Trace("tasks/take_ownership:Run() Leaving")
	fmt.Println("Running setup task: take-ownership")

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	if *task.ownerSecretKey == nil {

		// If TPM_OWNER_SECRET was omitted from the answer file/env, then
		// the expectation is that the user wants the Trust-Agent to generate
		// an owner-secret.  This requires that the TPM is clear and/or has
		// an empty string for the owner password.

		emptyOwner, err := tpm.IsOwnedWithAuth("")
		if err != nil {
			return errors.Wrap(err, "Runtime error while checking the empty owner-secret")
		}

		if emptyOwner {
			fmt.Println("take-ownership: Generating new TPM owner-secret")

			newSecretKey, err := crypt.GetHexRandomString(20)
			if err != nil {
				return errors.Wrap(err, "Error while generating a owner-secret")
			}

			err = tpm.TakeOwnership(newSecretKey)
			if err != nil {
				return errors.Wrap(err, "Error performing takeownership with the generated owner-secret")
			}

			*task.ownerSecretKey = &newSecretKey

		} else {
			return errors.New("The TPM must be in a clear state for take-ownerhsip to generate a new owner-secret")
		}

	} else {

		// The TPM_OWNER_SECRET was provided in the answer file/env and could be
		// empty ("") or any string value.  There are three conditions to handle...
		//
		// - The TPM's owner-secret has been previously set and the customer has provided
		//   it in the TPM_OWNER_SECRET.  'IsOwnedWithAuth(TPM_OWNER_SECRET)' will return true
		//   and provisioning should successfully complete (i.e., the owner-secret
		//   password has owner access to the TPM).
		// - The TPM is in a clear state (the empty password can be used for owner access)
		//   and the user provided the value of TPM_OWNER_SECRET -- they want take-ownership
		//   using that value.  In this case, 'IsOwnedWithAuth(TPM_OWNER_SECRET)' will
		//   return false but 'IsOwnedWithAuth("")' will return true (and the Trust-Agent
		//   can take-ownership with the provide owner-secret).  TPM provisioning should
		//   be successfull.
		// - The TPM is NOT clear and and the user provided the value of TPM_OWNER_SECRET.
		//   'IsOwnedWithAuth(TPM_OWNER_SECRET)' will return false and so will 'IsOwnedWithAuth("")'.
		//   TPM provisioning will fail because the wrong password has been provided.
		// - The provided secret is empty:  The customer doesn't want to take-ownership
		//   and expects the provisioning to succeed.  If the TPM can be access with the
		//   empty password then TPM provisioning should succeed (otherwise it will fail
		//   because the password is different).
		//
		owned, err := tpm.IsOwnedWithAuth(**task.ownerSecretKey)
		if err != nil {
			return errors.Wrap(err, "Runtime error while checking the provided owner-secret")
		}

		if !owned && **task.ownerSecretKey == "" {

			return errors.New("The empty ownership password was provided but the TPM is not in a clear state")

		} else if !owned {

			fmt.Println("take-ownership: Attempting to take-ownership with the provided owner-secret")

			owned, err := tpm.IsOwnedWithAuth("")
			if err != nil {
				return errors.Wrap(err, "Runtime error while checking the owner-secret")
			}

			if !owned {
				return errors.New("The TPM must be in a clear state for take-ownerhsip with the provided owner-secret")
			}

			err = tpm.TakeOwnership(**task.ownerSecretKey)
			if err != nil {
				return errors.Wrap(err, "Error performing takeownership with the provided owner-secret")
			}
		}
	}

	return nil
}

//
// Checks the validity of the owner-secret using TpmProvider.IsOwnedWithAuth.
//
func (task *TakeOwnership) Validate(c setup.Context) error {
	log.Trace("tasks/take_ownership:Validate() Entering")
	defer log.Trace("tasks/take_ownership:Validate() Leaving")

	if task.ownerSecretKey == nil {
		return errors.New("The owner-secret cannot be nil")
	}

	tpmProvider, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpmProvider.Close()

	ok, err := tpmProvider.IsOwnedWithAuth(**task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Error while checking if the tpm is already owned with the current secret key")
	}

	if !ok {
		return errors.New("The tpm is not owned with the current secret key")
	}

	log.Debug("tasks/take_ownership:Validate() Take ownership was successful.")
	return nil
}
