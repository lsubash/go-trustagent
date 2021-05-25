/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"fmt"
	"intel/isecl/go-trust-agent/v4/config"

	commLog "github.com/intel-secl/intel-secl/v4/pkg/lib/common/log"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type RequestHandler interface {
	GetTpmQuote(quoteRequest *taModel.TpmQuoteRequest) (*taModel.TpmQuoteResponse, error)
	GetHostInfo() (*taModel.HostInfo, error)
	GetAikDerBytes() ([]byte, error)
	DeployAssetTag(*taModel.TagWriteRequest) error
	GetBindingCertificateDerBytes() ([]byte, error)
	DeploySoftwareManifest(*taModel.Manifest) error
	GetApplicationMeasurement(*taModel.Manifest) (*taModel.Measurement, error)
}

func NewRequestHandler(cfg *config.TrustAgentConfiguration) RequestHandler {
	return &requestHandlerImpl{
		cfg: cfg,
	}
}

type requestHandlerImpl struct {
	cfg *config.TrustAgentConfiguration
}

type EndpointError struct {
	Message    string
	StatusCode int
}

func (e EndpointError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}
