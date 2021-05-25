/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/pem"
	"errors"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	"intel/isecl/go-trust-agent/v4/constants"
	"io/ioutil"
	"net/http"
	"os"
)

func (handler *requestHandlerImpl) GetBindingCertificateDerBytes() ([]byte, error) {
	bindingKeyBytes, err := getBindingKeyPem()
	if err != nil {
		return nil, err
	}

	bindingKeyDer, _ := pem.Decode(bindingKeyBytes)
	if bindingKeyDer == nil {
		return nil, errors.New("There was an error parsing the Binding Key's der bytes")
	}

	return bindingKeyDer.Bytes, nil
}

func getBindingKeyPem() ([]byte, error) {
	if _, err := os.Stat(constants.BindingKeyCertificatePath); os.IsNotExist(err) {
		log.WithError(err).Errorf("common/binding_key_certificate:getBindingKeyCertificate() %s - %s does not exist", message.AppRuntimeErr, constants.BindingKeyCertificatePath)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	bindingKeyBytes, err := ioutil.ReadFile(constants.BindingKeyCertificatePath)
	if err != nil {
		log.Errorf("common/binding_key_certificate:getBindingKeyCertificate() %s - Error reading %s", message.AppRuntimeErr, constants.BindingKeyCertificatePath)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

	}

	return bindingKeyBytes, nil
}
