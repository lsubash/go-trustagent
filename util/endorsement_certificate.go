/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package util

import (
	"crypto/x509"
	"encoding/asn1"
	"intel/isecl/lib/tpmprovider/v4"

	"github.com/pkg/errors"
)

func GetEndorsementKeyCertificateBytes(ownerSecretKey string) ([]byte, error) {
	log.Trace("util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Entering")
	defer log.Trace("util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Leaving")

	tpmFactory, err := tpmprovider.NewTpmFactory()
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Could not create tpm factory")
	}

	//---------------------------------------------------------------------------------------------
	// Get the endorsement key certificate from the tpm
	//---------------------------------------------------------------------------------------------
	tpm, err := tpmFactory.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	// check to see if the EK Certificate exists...
	ekCertificateExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return nil, errors.Wrap(err, "Error checking if the EK Certificate is present")
	}

	if !ekCertificateExists {
		return nil, errors.Errorf("The TPM does not have an RSA EK Certificate at the default index 0x%x", tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	}

	ekCertBytes, err := tpm.NvRead(ownerSecretKey, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error while performing tpm Nv read operation for getting endorsement certificate in bytes")
	}

	ekCertBytes, err = trimEkCertForTrailingData(ekCertBytes)
	if err != nil {
		return nil, err
	}

	// check if the multi-level EK issuer cert chain is provisioned
	// check to see if the EK Certificate exists...
	eccOnDieCaCertChainExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_X509_P384_EK_CERTCHAIN)
	if err != nil {
		return nil, errors.Wrap(err, "Error checking if the EK Issuing Cert Chain is present")
	}

	// cert chain exists - proceed to retrieve
	if eccOnDieCaCertChainExists {
		issuingCertChainBytes, err := tpm.NvRead(ownerSecretKey, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_X509_P384_EK_CERTCHAIN)
		if err != nil {
			return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error "+
				"while performing tpm Nv read operation for getting endorsement certificate chain in bytes")
		}

		// assemble the full EC chain with the issuing certificates first
		var fullChainBytes []byte
		fullChainBytes = append(fullChainBytes, issuingCertChainBytes...)
		fullChainBytes = append(fullChainBytes, ekCertBytes...)
		ekCertBytes = fullChainBytes
	}
	return ekCertBytes, nil
}

// ISECL-12285: Trims the trailing data if there are any at the end of tpm endorsement certificate.
// Its been observed in few of endorsement certificate provisioned in TPM by vendors filling up the NV Index with additional 0s at the end of certificate bytes
// golang crypto x509.ParseCertificate and x509.ParseCertificates throws up error whenever it finds additional padding at the end of der encoded certificate bytes.
// This function trims the additional bytes if it finds at the end of tpm endorsement certificate bytes.
// asn1.Unmarshal enables us to determine the actual length of trailing data, in which it returns the trailing data, using which length of trailing data could be determined and trimmed off
func trimEkCertForTrailingData(ekCertBytes []byte) ([]byte, error) {
	var cert asn1.RawValue
	rest, err := asn1.Unmarshal(ekCertBytes, &cert)
	if len(rest) > 0 && err == nil {
		_, err := x509.ParseCertificate(ekCertBytes[:len(ekCertBytes)-len(rest)])
		if err != nil {
			return nil, errors.Wrap(err, "Error while parsing endorsement certificate in bytes into x509 certificate")
		}
		return ekCertBytes[:len(ekCertBytes)-len(rest)], nil
	} else if err != nil {
		return nil, errors.Wrap(err, "Error while asn1 unmarshalling endorsement certificate in bytes")
	}
	return ekCertBytes, nil
}
