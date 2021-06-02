/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/go-trust-agent/v4/config"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/lib/tpmprovider/v4"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v4/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	TpmSecretKey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
)

//
// These tests can be run (in tpm-devel container) via...
//   env CGO_CFLAGS_ALLOW="-f.*" go test -v -tags unit_test -run TestTakeOwnership* intel/isecl/go-trust-agent/v4/tasks
//

func runTakeOwnership(t *testing.T, mockedTpmFactory tpmprovider.MockedTpmFactory, ownerSecret **string) error {

	takeOwnership := TakeOwnership{tpmFactory: mockedTpmFactory, ownerSecretKey: ownerSecret}

	err := takeOwnership.Run(setup.Context{})
	if err != nil {
		return err
	}

	return nil
}

// If the owner-secret is nil (not defined in answer file) and the
// TPM is in a clear state, expect the task to generate a 40 character
// password and use it to take-ownership of the TPM.
func TestTakeOwnershipNilSecretClearTPM(t *testing.T) {

	// mock "clear" TPM
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	var ownerSecret *string
	err := runTakeOwnership(t, mockedTpmFactory, &ownerSecret)
	if err != nil {
		t.Fatal(err) // unexpected
	}

	if ownerSecret == nil {
		t.Fatalf("The owner-secret was not generated")
	} else if len(*ownerSecret) != 40 {
		t.Fatalf("The generated owner-secret had an invalid length")
	}

	t.Logf("Successfully generated owner-secret '%s'", *ownerSecret)
}

// If the owner-secret is nil (not defined in answer file) and the
// TPM is not in a clear state, expect take-ownership to fail because
// the default, empty password can't get owner access.
func TestTakeOwnershipNilSecretNotClearTPM(t *testing.T) {

	// mock a "not cleared" TPM (i.e., that fails when "" is used for
	// the owner-secret).
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything).Return(errors.New(""))
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(false, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	var ownerSecret *string
	err := runTakeOwnership(t, mockedTpmFactory, &ownerSecret)
	if err == nil {
		t.Fatalf("The unit test expected take-ownership to fail")
	}

	t.Log(err)
}

// If the empty password is provided (TPM_OWNER_SECRET="") and
// the TPM is in a clear state, expect take-ownership to be successful.
func TestTakeOwnershipEmptySecretClearTPM(t *testing.T) {

	// mock "clear" TPM
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	ownerSecret := string("")
	results := &ownerSecret
	err := runTakeOwnership(t, mockedTpmFactory, &results)
	if err != nil {
		t.Fatal(err) // unexpected
	}

	if *results != ownerSecret {
		t.Fatalf("The owner-secret was not generated")
	}
}

// If the empty password is provided (TPM_OWNER_SECRET="") and
// the TPM has a different owner-secret expect take-ownership to fail.
func TestTakeOwnershipEmptySecretNotClearTPM(t *testing.T) {

	// mock a "not cleared" TPM (i.e., that fails when "" is used for
	// the owner-secret).
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything).Return(errors.New(""))
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(false, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	ownerSecret := string("")
	results := &ownerSecret
	err := runTakeOwnership(t, mockedTpmFactory, &results)
	if err == nil {
		t.Fatalf("The unit test expected take-ownership to fail")
	}

	t.Log(err)
}

// If the owner-secret is provided  (TPM_OWNER_SECRET="xyz") and
// the TPM is clear, the task should fail because the provided
// secret can't access the TPM.
func TestTakeOwnershipProvidedSecretClearTPM(t *testing.T) {

	// mock "clear" TPM
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", TpmSecretKey).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", TpmSecretKey).Return(false, nil)
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	ownerSecret := string(TpmSecretKey)
	results := &ownerSecret
	err := runTakeOwnership(t, mockedTpmFactory, &results)
	if err == nil {
		t.Fatalf("The unit test expected take-ownership to fail")
	}

}

// If the empty password is provided (TPM_OWNER_SECRET="xyz") and
// the TPM is owned with that password, expect take-ownership to be
// successful.
func TestTakeOwnershipProvidedSecretThatOwnsTPM(t *testing.T) {

	// TPM that is owned by 'TpmSecretKey'
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", TpmSecretKey).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", TpmSecretKey).Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	ownerSecret := string(TpmSecretKey)
	results := &ownerSecret
	err := runTakeOwnership(t, mockedTpmFactory, &results)
	if err != nil {
		t.Fatal(err) // unexpected
	}

	if *results != ownerSecret {
		t.Fatalf("The owner-secret was not generated")
	}
}

func TestCreateHostDefault(t *testing.T) {
	assert := assert.New(t)

	cfg := &config.TrustAgentConfiguration{}
	cfg.WebService.Port = 8045

	// create mocks that return no hosts on 'SearchHosts' (i.e. host does not exist in hvs) and
	// host with an new id for 'CreateHost'
	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{}}, nil)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostsClient}

	context := setup.Context{}

	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	createHost := CreateHost{clientFactory: mockedVSClientFactory, trustAgentPort: cfg.WebService.Port}
	err := createHost.Run(context)
	assert.NoError(err)
}

func TestCreateHostExisting(t *testing.T) {
	assert := assert.New(t)

	cfg := &config.TrustAgentConfiguration{}
	cfg.WebService.Port = 8045
	hwUuid := uuid.MustParse("8032632b-8fa4-e811-906e-00163566263e")
	existingHost := hvs.Host{
		Id:               uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723d"),
		HostName:         "ta.server.com",
		Description:      "GTA RHEL 8.0",
		ConnectionString: "https://ta.server.com:1443",
		HardwareUuid:     &hwUuid,
	}

	// create mocks that return a host (i.e. it exists in hvs)
	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{&existingHost}}, nil)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostsClient}

	context := setup.Context{}
	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	createHost := CreateHost{clientFactory: mockedVSClientFactory, trustAgentPort: cfg.WebService.Port}
	err := createHost.Run(context)
	assert.Error(err)
}
