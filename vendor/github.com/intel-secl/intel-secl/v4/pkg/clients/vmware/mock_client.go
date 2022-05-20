/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vmware

//go:generate mockgen -destination=mock_client.go -package=vmware github.com/intel-secl/intel-secl/v4/pkg/lib/clients/vmware VMWareClient

import (
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"github.com/stretchr/testify/mock"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

type MockVMWareClient struct {
	mock.Mock
}

func NewMockVMWareClient() (*MockVMWareClient, error) {
	mockVMWareClient := MockVMWareClient{}
	return &mockVMWareClient, nil
}

func (vm *MockVMWareClient) GetHostInfo() (taModel.HostInfo, error) {
	args := vm.Called()
	return args.Get(0).(taModel.HostInfo), args.Error(1)
}

func (vm *MockVMWareClient) GetTPMAttestationReport() (*types.QueryTpmAttestationReportResponse, error) {
	args := vm.Called()
	return args.Get(0).(*types.QueryTpmAttestationReportResponse), args.Error(1)
}

func (vm *MockVMWareClient) GetVmwareClusterReference(string) ([]mo.HostSystem, error) {
	args := vm.Called()
	return args.Get(0).([]mo.HostSystem), args.Error(1)
}
