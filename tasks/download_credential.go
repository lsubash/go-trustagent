/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/lib/common/v4/setup"
	"io/ioutil"
	"os"

	"github.com/intel-secl/intel-secl/v4/pkg/clients"
	"github.com/intel-secl/intel-secl/v4/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	types "github.com/intel-secl/intel-secl/v4/pkg/model/aas"
	"github.com/pkg/errors"
)

type DownloadCredential struct {
	aasUrl string
	hostId string
}

//
// Downloads Credential file for message queue server from AAS
//
func (task *DownloadCredential) Run(c setup.Context) error {
	log.Trace("tasks/download_credential:Run() Entering")
	defer log.Trace("tasks/download_credential:Run() Leaving")

	var err error
	fmt.Println("Running setup task: download-credential")

	bearerToken, err := c.GetenvSecret("BEARER_TOKEN", "bearer token")
	if bearerToken == "" || err != nil {
		return errors.Errorf(" %s is not set", constants.EnvBearerToken)
	}

	if task.hostId == "" {
		return errors.Errorf("%s is not set", constants.EnvTAHostId)
	}

	if task.aasUrl == "" {
		return errors.Errorf("%s is not set", constants.EnvAASBaseURL)
	}

	caCerts, err := crypt.GetCertsFromDir(constants.TrustedCaCertsDir)
	if err != nil {
		log.WithError(err).Errorf("tasks/download_credential:Run() Error while reading certs from %s", constants.TrustedCaCertsDir)
		return err
	}

	client, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		log.WithError(err).Error("tasks/download_credential:Run() Error while creating http client")
		return err
	}

	aasClient := aas.Client{
		BaseURL:    task.aasUrl,
		JWTToken:   []byte(bearerToken),
		HTTPClient: client,
	}

	params := types.Parameters{
		TaHostId: &task.hostId,
	}
	createCredntialReq := types.CreateCredentialsReq{
		ComponentType: constants.TAServiceName,
		Parameters:    &params,
	}
	credentialFileBytes, err := aasClient.GetCredentials(createCredntialReq)
	if err != nil {
		return errors.Wrap(err, "Error while retrieving credential file from aas")
	}

	err = ioutil.WriteFile(constants.NatsCredentials, credentialFileBytes, 0600)
	if err != nil {
		return errors.Wrapf(err, "Error while saving %s", constants.NatsCredentials)
	}

	return nil
}

// Assume task is successful if nats credential file already exists
func (task *DownloadCredential) Validate(c setup.Context) error {
	log.Trace("tasks/download_credential:Validate() Entering")
	defer log.Trace("tasks/download_credential:Validate() Leaving")

	_, err := os.Stat(constants.NatsCredentials)
	if os.IsNotExist(err) {
		return errors.Errorf("%s file does not exist", constants.NatsCredentials)
	}

	log.Info("tasks/download_credential:Validate() download-credentials setup task was successful.")
	return nil
}
