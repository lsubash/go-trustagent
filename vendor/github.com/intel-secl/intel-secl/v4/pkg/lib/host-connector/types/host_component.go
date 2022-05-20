/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

type HostComponent string

const (
	HostComponentTagent  HostComponent = "tagent"
	HostComponentWlagent HostComponent = "wlagent"
)

func (hc HostComponent) String() string {
	return string(hc)
}

type OsName string

const (
	OsWindows       OsName = "WINDOWS"
	OsWindows2k16   OsName = "MICROSOFT WINDOWS SERVER 2016 STANDARD"
	OsWindows2k16dc OsName = "MICROSOFT WINDOWS SERVER 2016 DATACENTER"
	OsVMware        OsName = "VMWARE ESXI"
)

func (on OsName) String() string {
	return string(on)
}
