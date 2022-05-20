/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"bytes"
	"encoding/json"
	"github.com/intel-secl/intel-secl/v4/pkg/clients/util"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/validation"
	"github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
)

type ReportsClient interface {
	CreateSAMLReport(hvs.ReportCreateRequest) ([]byte, error)
}

type reportsClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client reportsClientImpl) CreateSAMLReport(reportCreateRequest hvs.ReportCreateRequest) ([]byte, error) {
	log.Trace("hvsclient/reports_client:CreateSAMLReport() Entering")
	defer log.Trace("hvsclient/reports_client:CreateSAMLReport() Leaving")

	jsonData, err := json.Marshal(reportCreateRequest)
	if err != nil {
		return nil, err
	}

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/reports_client:CreateSAMLReport() Configured HVS URL is malformed")
	}
	reports, _ := parsedUrl.Parse("reports")
	endpoint := parsedUrl.ResolveReference(reports)
	req, err := http.NewRequest("POST", endpoint.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/reports_client:CreateSAMLReport() Failed to instantiate http request to HVS")
	}

	req.Header.Set("Accept", "application/samlassertion+xml")
	req.Header.Set("Content-Type", "application/json")

	var samlReport []byte
	if client.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
		rsp, err := client.httpClient.Do(req)
		if err != nil {
			log.Error("hvsclient/reports_client:CreateSAMLReport() Error while sending request from client to server")
			log.Tracef("%+v", err)
			return nil, err
		}
		samlReport, err = ioutil.ReadAll(rsp.Body)
		if err != nil {
			log.Error("hvsclient/reports_client:CreateSAMLReport() Error while reading response body")
			return nil, err
		}
	} else {
		certs, err := crypt.GetCertsFromDir(client.cfg.CaCertsDir)
		if err != nil {
			return nil, errors.Wrap(err, "hvsclient/reports_client:CreateSAMLReport() Error while retrieving ca certs from dir")
		}
		samlReport, err = util.SendRequest(req, client.cfg.AasAPIUrl, client.cfg.UserName, client.cfg.Password, certs)
		if err != nil {
			log.Error("hvsclient/reports_client:CreateSAMLReport() Error while sending request")
			return nil, err
		}
	}

	// now validate SAML
	err = validation.ValidateXMLString(string(samlReport))
	if err != nil {
		return nil, err
	}

	return samlReport, nil
}
