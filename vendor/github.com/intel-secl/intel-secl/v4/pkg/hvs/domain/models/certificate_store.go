/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"crypto"
	"crypto/x509"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/crypt"
	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log"
	"github.com/pkg/errors"
	"strings"
)

var defaultLog = log.GetDefaultLogger()

// CertificatesStore reads and caches map of certificate type and CertificateStore in application
type CertificatesStore map[string]*CertificateStore

// CertificateStore holds file/directory path and certificates collection
type CertificateStore struct {
	Key          crypto.PrivateKey
	CertPath     string
	Certificates []x509.Certificate
}

// CertificatesPathStore
type CertificatesPathStore map[string]CertLocation //map of certificate type and associated locations

type CertLocation struct {
	KeyFile  string
	CertPath string // Can hold either certFile or certDir
}

func (cs *CertificatesStore) GetPath(certType string) string {
	certStore := (*cs)[certType]
	return certStore.CertPath
}

func (cs *CertificatesStore) AddCertificatesToStore(certType, certFile string, certificate *x509.Certificate) error {
	defaultLog.Trace("models/certificate_store:AddCertificatesToStore() Entering")
	defer defaultLog.Trace("models/certificate_store:AddCertificatesToStore() Leaving")

	certStore := (*cs)[certType]
	// Save certificate to file with common name
	certPath := certStore.CertPath + strings.Replace(certFile, " ", "", -1) + ".pem"
	err := crypt.SavePemCert(certificate.Raw, certPath)
	if err != nil {
		return errors.Errorf("Failed to store certificate %s", certPath)
	}

	// Add certificate to store
	certStore.Certificates = append(certStore.Certificates, *certificate)

	return nil
}

func (cs *CertificatesStore) GetKeyAndCertificates(certType string) (crypto.PrivateKey, []x509.Certificate, error) {
	defaultLog.Trace("models/certificate_store:GetKeyAndCertificates() Entering")
	defer defaultLog.Trace("models/certificate_store:GetKeyAndCertificates() Leaving")

	certStore := (*cs)[certType]
	if certStore != nil {
		return certStore.Key, certStore.Certificates, nil
	}
	return nil, nil, errors.Errorf("Certificate store is empty for certType: %s", certType)
}

// This function expects CN to be unique, use this only in that scenario
func (cs *CertificatesStore) RetrieveCertificate(certType, commonName string) (*x509.Certificate, error) {
	defaultLog.Trace("models/certificate_store:RetrieveCertificate() Entering")
	defer defaultLog.Trace("models/certificate_store:RetrieveCertificate() Leaving")

	certStore := (*cs)[certType]
	if certStore != nil {
		for _, cert := range certStore.Certificates {
			if cert.Issuer.CommonName == strings.ReplaceAll(commonName, "\\x00", "") {
				return &cert, nil
			}
		}
	}

	return nil, nil
}
