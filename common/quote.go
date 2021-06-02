/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"intel/isecl/go-trust-agent/v4/config"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/lib/tpmprovider/v4"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/intel-secl/intel-secl/v4/pkg/lib/common/log/message"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"github.com/pkg/errors"
)

func (handler *requestHandlerImpl) GetTpmQuote(quoteRequest *taModel.TpmQuoteRequest) (*taModel.TpmQuoteResponse, error) {

	tpmFactory, err := tpmprovider.NewTpmFactory()
	if err != nil {
		return nil, err
	}

	tpm, err := tpmFactory.NewTpmProvider()
	if err != nil {
		log.WithError(err).Errorf("common/quote:getTpmQuote() %s - Error creating tpm provider", message.AppRuntimeErr)
		return nil, err
	}
	defer tpm.Close()

	return CreateTpmQuoteResponse(handler.cfg, tpm, quoteRequest)
}

func CreateTpmQuoteResponse(cfg *config.TrustAgentConfiguration, tpm tpmprovider.TpmProvider, tpmQuoteRequest *taModel.TpmQuoteRequest) (*taModel.TpmQuoteResponse, error) {

	var err error

	log.Infof("TpmQuoteRequest: %+v", tpmQuoteRequest)

	if len(tpmQuoteRequest.Nonce) == 0 {
		secLog.Errorf("common/quote:CreateTpmQuoteResponse() %s - The TpmQuoteRequest does not contain a nonce", message.InvalidInputProtocolViolation)
		return nil, errors.New("The TpmQuoteRequest does not contain a nonce")
	}

	// ISECL-12121: strip inactive PCR Banks from the request
	if tpmQuoteRequest == nil || len(tpmQuoteRequest.PcrBanks) == 0 {
		tpmQuoteRequest.PcrBanks = []string{string(constants.SHA384), string(constants.SHA256), string(constants.SHA1)}
	}

	for i, pcrBank := range tpmQuoteRequest.PcrBanks {
		isActive, err := tpm.IsPcrBankActive(pcrBank)
		if !isActive {
			log.Infof("common/quote:CreateTpmQuoteResponse() %s PCR bank is inactive. Dropping from quote request. %s",
				pcrBank, err.Error())
			tpmQuoteRequest.PcrBanks = append(tpmQuoteRequest.PcrBanks[:i], tpmQuoteRequest.PcrBanks[i+1:]...)
		} else if err != nil {
			log.WithError(err).Errorf("common/quote:CreateTpmQuoteResponse() Error while determining PCR bank "+
				"%s state: %s", pcrBank, err.Error())
		}
	}

	tpmQuoteResponse, err := createTpmQuote(cfg.Tpm.TagSecretKey, tpm, tpmQuoteRequest)
	if err != nil {
		log.WithError(err).Errorf("common/quote:CreateTpmQuoteResponse() %s - Error while creating the tpm quote", message.AppRuntimeErr)
		return nil, err
	}

	return tpmQuoteResponse, nil
}

// HVS generates a 20 byte random nonce that is sent in the tpmQuoteRequest.  However,
// HVS expects the response nonce (in the TpmQuoteResponse.Quote binary) to be hashed with the bytes
// of local ip address.  If this isn't performed, HVS will throw an error when the
// response is received.
//
// Also, HVS takes into account the asset tag in the nonce -- it takes the ip hashed nonce
// and 'extends' it with value of asset tag (i.e. when tags have been set on the trust agent).
func getNonce(tpmQuoteRequest *taModel.TpmQuoteRequest, assetTag string) ([]byte, error) {
	log.Trace("common/quote:getNonce() Entering")
	defer log.Trace("common/quote:getNonce() Leaving")

	log.Debugf("common/quote:getNonce() Received HVS nonce '%s', raw[%s]", base64.StdEncoding.EncodeToString(tpmQuoteRequest.Nonce), hex.EncodeToString(tpmQuoteRequest.Nonce))

	// similar to HVS' SHA1.digestOf(hvsNonce).extend(ipBytes)
	hash := sha1.New()
	_, err := hash.Write(tpmQuoteRequest.Nonce)
	if err != nil {
		return nil, err
	}
	taNonce := hash.Sum(nil)

	if assetTag != "" {

		tagBytes, err := base64.StdEncoding.DecodeString(assetTag)
		if err != nil {
			return nil, err
		}

		// similar to HVS' SHA1.digestOf(taNonce).extend(tagBytes)
		hash = sha1.New()
		_, err = hash.Write(taNonce)
		if err != nil {
			return nil, err
		}
		_, err = hash.Write(tagBytes)
		if err != nil {
			return nil, err
		}
		taNonce = hash.Sum(nil)

		log.Debugf("common/quote:getNonce() Used tag bytes '%s' to extend nonce to '%s', raw[%s]", hex.EncodeToString(tagBytes), base64.StdEncoding.EncodeToString(taNonce), hex.EncodeToString(taNonce))
	}

	return taNonce, nil
}

func readAikAsBase64() (string, error) {
	log.Trace("common/quote:readAikAsBase64() Entering")
	defer log.Trace("common/quote:readAikAsBase64() Leaving")

	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		return "", err
	}

	aikBytes, err := ioutil.ReadFile(constants.AikCert)
	if err != nil {
		return "", errors.Wrapf(err, "common/quote:readAikAsBase64() Error reading file %s", constants.AikCert)
	}

	return base64.StdEncoding.EncodeToString(aikBytes), nil
}

func readEventLog() (string, error) {
	log.Trace("common/quote:readEventLog() Entering")
	defer log.Trace("common/quote:readEventLog() Leaving")

	if _, err := os.Stat(constants.MeasureLogFilePath); os.IsNotExist(err) {
		log.Debugf("esource/quote:readEventLog() Event log file '%s' was not present", constants.MeasureLogFilePath)
		return "", nil // If the file does not exist, do not include in the quote
	}

	eventLogBytes, err := ioutil.ReadFile(constants.MeasureLogFilePath)
	if err != nil {
		return "", errors.Wrapf(err, "common/quote:readEventLog() Error reading file: %s", constants.MeasureLogFilePath)
	}

	// Make sure the bytes are valid json
	err = json.Unmarshal(eventLogBytes, new(interface{}))
	if err != nil {
		return "", errors.Wrap(err, "common/quote:readEventLog() Error while unmarshalling event log")
	}

	return string(eventLogBytes), nil
}

func getQuote(tpm tpmprovider.TpmProvider, tpmQuoteRequest *taModel.TpmQuoteRequest, nonce []byte) (string, error) {

	log.Debugf("common/quote:getQuote() Providing tpm nonce value '%s', raw[%s]", base64.StdEncoding.EncodeToString(nonce), hex.EncodeToString(nonce))
	quoteBytes, err := tpm.GetTpmQuote(nonce, tpmQuoteRequest.PcrBanks, tpmQuoteRequest.Pcrs)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(quoteBytes), nil
}

// create an array of "tcbMeasurments", each from the  xml escaped string
// of the files located in /opt/trustagent/var/ramfs
func getTcbMeasurements() ([]string, error) {
	log.Trace("common/quote:getTcbMeasurements() Entering")
	defer log.Trace("common/quote:getTcbMeasurements() Leaving")

	measurements := []string{}

	fileInfo, err := ioutil.ReadDir(constants.RamfsDir)
	if err != nil {
		return nil, err
	}

	for _, file := range fileInfo {
		if filepath.Ext(file.Name()) == ".xml" {
			log.Debugf("common/quote:getTcbMeasurements() Including measurement file '%s/%s'", constants.RamfsDir, file.Name())
			xml, err := ioutil.ReadFile(constants.RamfsDir + file.Name())
			if err != nil {
				return nil, errors.Wrapf(err, "common/quote:getTcbMeasurements() Error reading manifest file %s", file.Name())
			}

			measurements = append(measurements, string(xml))
		}
	}

	return measurements, nil
}

func getAssetTags(tagSecretKey string, tpm tpmprovider.TpmProvider) (string, error) {
	log.Trace("common/quote:getAssetTags() Entering")
	defer log.Trace("common/quote:getAssetTags() Leaving")

	tagExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return "", errors.Wrap(err, "common/quote:getAssetTags() Error while checking existence of Nv Index")
	}

	if !tagExists {
		log.Warn("The asset tag nvram is not present")
		return "", nil
	}

	indexBytes, err := tpm.NvRead(tagSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return "", errors.Wrap(err, "resource/quote:getAssetTags() Error while performing tpm nv read operation")
	}

	if len(indexBytes) < 2 {
		return "", errors.New("Invalid tag index length")
	}

	tagLength := uint16(0)
	r := bytes.NewReader(indexBytes)
	err = binary.Read(r, binary.LittleEndian, &tagLength)
	if err != nil {
		return "", errors.Wrap(err, "Failed to read asset tag length")
	}

	if tagLength == 0 {
		return "", nil
	} else if tagLength > constants.MaxHashLength {
		return "", fmt.Errorf("Invalid tag length %d", tagLength)
	}

	tagBytes := make([]byte, tagLength)
	l, err := r.Read(tagBytes)
	if err != nil {
		return "", fmt.Errorf("Failed to read tag bytes with length %d", tagLength)
	}

	if l != int(tagLength) {
		return "", fmt.Errorf("The index contained length %d but only %d were read", tagLength, l)
	}

	return base64.StdEncoding.EncodeToString(tagBytes), nil // this data will be evaluated in 'getNonce'
}

func createTpmQuote(tagSecretKey string, tpm tpmprovider.TpmProvider, tpmQuoteRequest *taModel.TpmQuoteRequest) (*taModel.TpmQuoteResponse, error) {
	log.Trace("common/quote:createTpmQuote() Entering")
	defer log.Trace("common/quote:createTpmQuote() Leaving")

	var err error

	tpmQuoteResponse := &taModel.TpmQuoteResponse{
		TimeStamp: time.Now().Unix(),
	}

	// getAssetTags must be called before getQuote so that the nonce is created correctly - see comments for getNonce()
	tpmQuoteResponse.AssetTag, err = getAssetTags(tagSecretKey, tpm)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while retrieving asset tags")
	}

	if tpmQuoteResponse.AssetTag != "" {
		tpmQuoteResponse.IsTagProvisioned = true
	}

	nonce, err := getNonce(tpmQuoteRequest, tpmQuoteResponse.AssetTag)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while generting nonce")
	}

	log.Infof("NONCE: %+v", nonce)

	// get the quote from tpmprovider
	tpmQuoteResponse.Quote, err = getQuote(tpm, tpmQuoteRequest, nonce)
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while retrieving tpm quote request")
	}

	// aik --> read from disk and convert to PEM string
	tpmQuoteResponse.Aik, err = readAikAsBase64()
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while reading Aik as Base64")
	}

	// eventlog: read /opt/trustagent/var/measure-log.json
	tpmQuoteResponse.EventLog, err = readEventLog()
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while reading event log")
	}

	tpmQuoteResponse.TcbMeasurements.TcbMeasurements, err = getTcbMeasurements()
	if err != nil {
		return nil, errors.Wrap(err, "common/quote:createTpmQuote() Error while retrieving TCB measurements")
	}

	// selected pcr banks (just return what was requested similar to java implementation)
	tpmQuoteResponse.SelectedPcrBanks.SelectedPcrBanks = tpmQuoteRequest.PcrBanks

	tpmQuoteResponse.ErrorCode = 0 // Question: does HVS handle specific error codes or is just a pass through?
	tpmQuoteResponse.ErrorMessage = "OK"
	return tpmQuoteResponse, nil
}
