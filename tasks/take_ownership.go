/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/lib/tpmprovider/v4"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	"github.com/pkg/errors"
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
				return errors.Wrap(err, "Error while performing tpm takeownership operation")
			}

			*task.ownerSecretKey = &newSecretKey

		} else {
			return errors.New("The TPM must be in a clear state to take-ownerhsip with a new owner-secret")
		}
	} else {
		owned, err := tpm.IsOwnedWithAuth(**task.ownerSecretKey)
		if err != nil {
			return errors.Wrap(err, "Runtime error while checking the owner-secret")
		}

		if !owned {
			return errors.New("The owner-secret could not be used to access the TPM.")
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

	log.Info("tasks/take_ownership:Validate() Take ownership was successful.")
	return nil
}
