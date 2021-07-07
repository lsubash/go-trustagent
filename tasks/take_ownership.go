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

type TakeOwnership struct {
	tpmFactory     tpmprovider.TpmFactory
	ownerSecretKey string
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

	//
	// Trust-Agent provisioning requires an owner-secret password to
	// access the TPM and provision the AK, NVRAM, etc.  For the most
	// part, this task checks that the TPM_OWNER_SECRET can access the TPM
	// with owner privileges.  It will take-ownership in the event that
	// a non-empty TPM_OWNER_SECRET was provided and the TPM has an empty
	// owner password ("").  Generally, the empty owner-secret is set when
	// a TPM is "cleared".
	//
	// There are really two scenarios -- either the TPM is clear and the empty
	// password can be used to change ownership, or the TPM is not clear and
	// the user must provide a valid owner-secret.
	//
	// If the TPM is clear, take-ownership will...
	// - Succeed if the empty password ("") is provided.  The empty password
	//   can be used to gain owner access during Trust-Agent provisioning.
	// - Attempt to take ownership with the value of TPM_OWNER_SECRET.  If
	//   successfull, provisioning will continue.  Otherwise, take-ownership
	//   will fail.
	//
	// If the TPM is not clear, then the TPM_OWNER_SECRET must be able to gain
	// owner access to the TPM so that provisioning will succeed.
	//

	owned, err := tpm.IsOwnedWithAuth(task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Runtime error while checking the provided owner-secret")
	}

	if !owned && task.ownerSecretKey == "" {
		// The provided password does not work and the user has provided
		// a non-empty password (i.e., that can be used when the TPM is
		// clear).  Since the TA does not support changing passwords and
		// would require the 'old' password, this is an error condition.
		return errors.New("The Trust-Agent only supports changing ownership when it is owned with the empty password.")
	} else if !owned {

		owned, err := tpm.IsOwnedWithAuth("")
		if err != nil {
			return errors.Wrap(err, "Runtime error while checking the empty owner-secret")
		}

		if !owned {
			return errors.New("The TPM must be in a clear state to take ownerhsip with a new owner-secret")
		}

		err = tpm.TakeOwnership(task.ownerSecretKey)
		if err != nil {
			return errors.Wrap(err, "Error performing take ownership with the provided owner-secret")
		}

		fmt.Println("take-ownership: Successfully took ownership of the TPM with the provided TPM_OWNER_SECRET")
	}

	return nil
}

//
// Checks the validity of the owner-secret using TpmProvider.IsOwnedWithAuth.
//
func (task *TakeOwnership) Validate(c setup.Context) error {
	log.Trace("tasks/take_ownership:Validate() Entering")
	defer log.Trace("tasks/take_ownership:Validate() Leaving")

	tpmProvider, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpmProvider.Close()

	owned, err := tpmProvider.IsOwnedWithAuth(task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Error while checking if the tpm is already owned with the owner-secret key")
	}

	if !owned {
		return errors.New("The tpm is not owned with the current secret key")
	}

	log.Debug("tasks/take_ownership:Validate() Take ownership was successful.")
	return nil
}
