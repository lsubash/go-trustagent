/*
* Copyright (C) 2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v4/pkg/clients"
	"github.com/intel-secl/intel-secl/v4/pkg/clients/aas"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	types "github.com/intel-secl/intel-secl/v4/pkg/model/aas"
	"github.com/pkg/errors"
	"intel/isecl/go-trust-agent/v4/config"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/lib/common/v4/setup"
)

type DownloadApiToken struct {
	aasUrl           string
	hostHardwareUUID string
	cfg              *config.TrustAgentConfiguration
}

//
// Downloads API Token from AAS
//
func (task *DownloadApiToken) Run(c setup.Context) error {
	log.Trace("tasks/download_api_token:Run() Entering")
	defer log.Trace("tasks/download_api_token:Run() Leaving")

	var err error
	fmt.Println("Running setup task: download-api-token")

	bearerToken, err := c.GetenvSecret("BEARER_TOKEN", "bearer token")
	if bearerToken == "" || err != nil {
		return errors.Errorf(" %s is not set", constants.EnvBearerToken)
	}

	if task.hostHardwareUUID == "" {
		return errors.Errorf("Host hardware UUID must be set to download API token from AAS")
	}

	if task.aasUrl == "" {
		return errors.Errorf("%s is not set", constants.EnvAASBaseURL)
	}

	caCerts, err := crypt.GetCertsFromDir(constants.TrustedCaCertsDir)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_api_token:Run() Error while reading certs from %s", constants.TrustedCaCertsDir)
	}

	client, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		return errors.Wrapf(err, "tasks/download_api_token:Run() Error while creating http client")
	}

	aasClient := aas.Client{
		BaseURL:    task.aasUrl,
		JWTToken:   []byte(bearerToken),
		HTTPClient: client,
	}

	permission := make(map[string]interface{})

	perms := []types.PermissionInfo{}
	perms = append(perms, types.PermissionInfo{
		Service: constants.VerificationServiceName,
		Rules:   []string{"reports:create:*"},
	})
	permission["permissions"] = perms

	createCustomerClaimsReq := types.CustomClaims{
		Subject:      task.hostHardwareUUID,
		ValiditySecs: constants.DefaultApiTokenExpiration,
		Claims:       permission,
	}

	apiTokenBytes, err := aasClient.GetCustomClaimsToken(createCustomerClaimsReq)
	if err != nil {
		return errors.Wrap(err, "Error while retrieving credential file from aas")
	}

	task.cfg.ApiToken = string(apiTokenBytes)
	err = task.cfg.Save()
	if err != nil {
		return errors.Wrap(err, "Error while saving API token from aas into TA configuration")
	}
	return nil
}

// Assume task is successful if API token is stored in config.yml already
func (task *DownloadApiToken) Validate(c setup.Context) error {
	log.Trace("tasks/download_api_token:Validate() Entering")
	defer log.Trace("tasks/download_api_token:Validate() Leaving")

	if task.cfg.ApiToken == "" {
		return errors.Errorf("API token does not exist in TA config.yml")
	}

	log.Debug("tasks/download_api_token:Validate() download_api_token setup task was successful.")
	return nil
}
