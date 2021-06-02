/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509/pkix"
	"intel/isecl/go-trust-agent/v4/config"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/go-trust-agent/v4/util"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/lib/tpmprovider/v4"
	"os"

	"github.com/intel-secl/intel-secl/v4/pkg/clients/hvsclient"
	commLog "github.com/intel-secl/intel-secl/v4/pkg/lib/common/log"
	"github.com/pkg/errors"
)

const (
	DefaultSetupCommand                    = "all"
	DownloadRootCACertCommand              = "download-ca-cert"
	DownloadCertCommand                    = "download-cert"
	TakeOwnershipCommand                   = "take-ownership"
	ProvisionAttestationIdentityKeyCommand = "provision-aik"
	DownloadPrivacyCACommand               = "download-privacy-ca"
	ProvisionPrimaryKeyCommand             = "provision-primary-key"
	CreateHostCommand                      = "create-host"
	CreateHostUniqueFlavorCommand          = "create-host-unique-flavor"
	GetConfiguredManifestCommand           = "get-configured-manifest"
	ProvisionAttestationCommand            = "provision-attestation"
	UpdateCertificatesCommand              = "update-certificates"
	UpdateServiceConfigCommand             = "update-service-config"
	DefineTagIndexCommand                  = "define-tag-index"
	DownloadCredentialCommand              = "download-credential"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func CreateTaskRunner(setupCmd string, cfg *config.TrustAgentConfiguration) (*setup.Runner, error) {
	log.Trace("tasks/task_runner:CreateTaskRunner() Entering")
	defer log.Trace("tasks/task_runner:CreateTaskRunner() Leaving")

	var vsClientFactory hvsclient.HVSClientFactory
	var tpmFactory tpmprovider.TpmFactory
	var err error
	var runner setup.Runner
	var ownerSecret *string

	if cfg == nil {
		return nil, errors.New("The cfg parameter was not provided")
	}

	//
	// There are three possible states to the TPM_OWNER_SECRET env var...
	// 1.) Not in env.  take-ownership should generate a new secret and attempt
	//     to take ownerhsip of the TPM (pass nil pointer to take-ownerhsip task).
	// 2.) In env but empty.  This is valid for customers that have cleared the TPM
	//     but don't want to take-ownership with a secret (pass the empty string so
	//     take-ownership can verify that empty-auth can access the TPM).
	// 3.) In env and not empty.  The customer has already taken ownership of TPM and
	//     has provided the password in TPM_OWNER_SECRET.  Similar to #2, pass the
	//     string into take-ownership and return an error if it can't be used to
	//     access the TPM.
	//
	envSecret, exists := os.LookupEnv(constants.EnvTPMOwnerSecret)
	if exists {
		ownerSecret = &envSecret
	} else {
		log.Infof("The TPM_OWNER_SECRET environment variable is not defined.")
	}

	switch setupCmd {
	case DefaultSetupCommand, ProvisionAttestationIdentityKeyCommand, ProvisionAttestationCommand,
		DownloadPrivacyCACommand, CreateHostCommand, CreateHostUniqueFlavorCommand, GetConfiguredManifestCommand:
		vsClientFactory, err = hvsclient.NewVSClientFactory(cfg.HVS.Url, util.GetBearerToken(),
			constants.TrustedCaCertsDir)
		if err != nil {
			return nil, errors.Wrap(err, "Could not create the hvsclient factory")
		}
		fallthrough

	case TakeOwnershipCommand, ProvisionPrimaryKeyCommand, DefineTagIndexCommand:
		switch setupCmd {
		case DefaultSetupCommand, ProvisionAttestationIdentityKeyCommand, ProvisionAttestationCommand,
			TakeOwnershipCommand, ProvisionPrimaryKeyCommand:
			tpmFactory, err = tpmprovider.NewTpmFactory()
			if err != nil {
				return nil, errors.Wrap(err, "Could not create tpm factory")
			}
		}
	}

	takeOwnershipTask := &TakeOwnership{
		tpmFactory:     tpmFactory,
		ownerSecretKey: &ownerSecret,
	}

	downloadRootCACertTask := &setup.Download_Ca_Cert{
		Flags:                []string{"--force"}, // to be consistent with other GTA tasks, always force update
		CmsBaseURL:           cfg.CMS.BaseURL,
		CaCertDirPath:        constants.TrustedCaCertsDir,
		TrustedTlsCertDigest: cfg.CMS.TLSCertDigest,
		ConsoleWriter:        os.Stdout,
	}

	downloadTLSCertTask := &setup.Download_Cert{
		Flags:              []string{"--force"}, // to be consistent with other GTA tasks, always force update
		KeyFile:            constants.TLSKeyFilePath,
		CertFile:           constants.TLSCertFilePath,
		KeyAlgorithm:       constants.DefaultKeyAlgorithm,
		KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
		CmsBaseURL:         cfg.CMS.BaseURL,
		Subject: pkix.Name{
			CommonName: cfg.TLS.CertCN,
		},
		SanList:       cfg.TLS.CertSAN,
		CertType:      "TLS",
		CaCertsDir:    constants.TrustedCaCertsDir,
		BearerToken:   "",
		ConsoleWriter: os.Stdout,
	}

	provisionAttestationIdentityKeyTask := &ProvisionAttestationIdentityKey{
		clientFactory:  vsClientFactory,
		tpmFactory:     tpmFactory,
		ownerSecretKey: &ownerSecret,
	}

	downloadPrivacyCATask := &DownloadPrivacyCA{
		clientFactory: vsClientFactory,
	}

	provisionPrimaryKeyTask := &ProvisionPrimaryKey{
		tpmFactory:     tpmFactory,
		ownerSecretKey: &ownerSecret,
	}

	downloadCredentialTask := &DownloadCredential{
		aasUrl: cfg.AAS.BaseURL,
		hostId: cfg.Nats.HostID,
	}

	createHostUniqueFlavorTask := &CreateHostUniqueFlavor{
		clientFactory:  vsClientFactory,
		trustAgentPort: cfg.WebService.Port,
	}

	getConfiguredManifestTask := &GetConfiguredManifest{
		clientFactory: vsClientFactory,
	}

	createHostTask := &CreateHost{
		clientFactory:  vsClientFactory,
		trustAgentPort: cfg.WebService.Port,
	}

	updateServiceConfigTask := &UpdateServiceConfig{
		cfg: &cfg,
	}

	defineTagIndexTask := &DefineTagIndex{
		tpmFactory:     tpmFactory,
		ownerSecretKey: &ownerSecret,
		assetTagSecret: &cfg.Tpm.TagSecretKey,
	}

	switch setupCmd {
	case ProvisionAttestationCommand:
		runner.Tasks = append(runner.Tasks, []setup.Task{downloadPrivacyCATask, takeOwnershipTask, defineTagIndexTask,
			provisionAttestationIdentityKeyTask, provisionPrimaryKeyTask}...)

	case UpdateCertificatesCommand:
		runner.Tasks = append(runner.Tasks, []setup.Task{downloadRootCACertTask, downloadTLSCertTask}...)

	case CreateHostCommand:
		runner.Tasks = append(runner.Tasks, createHostTask)

	case CreateHostUniqueFlavorCommand:
		runner.Tasks = append(runner.Tasks, createHostUniqueFlavorTask)

	case GetConfiguredManifestCommand:
		runner.Tasks = append(runner.Tasks, getConfiguredManifestTask)

	case DefaultSetupCommand:
		runner.Tasks = append(runner.Tasks, []setup.Task{updateServiceConfigTask, downloadRootCACertTask, downloadPrivacyCATask,
			takeOwnershipTask, defineTagIndexTask, provisionAttestationIdentityKeyTask, provisionPrimaryKeyTask}...)
		if cfg.Mode == constants.CommunicationModeOutbound {
			runner.Tasks = append(runner.Tasks, downloadCredentialTask)
		} else {
			runner.Tasks = append(runner.Tasks, downloadTLSCertTask)
		}

	case DownloadRootCACertCommand:
		runner.Tasks = append(runner.Tasks, downloadRootCACertTask)

	case DownloadCertCommand:
		runner.Tasks = append(runner.Tasks, downloadTLSCertTask)

	case DownloadPrivacyCACommand:
		runner.Tasks = append(runner.Tasks, downloadPrivacyCATask)

	case TakeOwnershipCommand:
		runner.Tasks = append(runner.Tasks, takeOwnershipTask)

	case ProvisionAttestationIdentityKeyCommand:
		runner.Tasks = append(runner.Tasks, provisionAttestationIdentityKeyTask)

	case ProvisionPrimaryKeyCommand:
		runner.Tasks = append(runner.Tasks, provisionPrimaryKeyTask)

	case UpdateServiceConfigCommand:
		runner.Tasks = append(runner.Tasks, updateServiceConfigTask)

	case DefineTagIndexCommand:
		runner.Tasks = append(runner.Tasks, defineTagIndexTask)

	case DownloadCredentialCommand:
		if cfg.Mode == constants.CommunicationModeOutbound {
			runner.Tasks = append(runner.Tasks, downloadCredentialTask)
		} else {
			return nil, errors.Errorf("cannot run download-credential task when %s is not set to %s", constants.EnvTAServiceMode, constants.CommunicationModeOutbound)
		}

	default:
		return nil, errors.New("Invalid setup command")
	}

	return &runner, nil
}
