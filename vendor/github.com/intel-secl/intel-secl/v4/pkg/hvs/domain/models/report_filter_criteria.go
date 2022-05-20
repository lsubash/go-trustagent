/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"github.com/google/uuid"
	"time"
)

type ReportFilterCriteria struct {
	ID             uuid.UUID
	HostID         uuid.UUID
	HostName       string
	HostHardwareID uuid.UUID
	HostStatus     string
	NumberOfDays   int
	FromDate       time.Time
	ToDate         time.Time
	LatestPerHost  bool
	Limit          int
}

type ReportLocator struct {
	ID     uuid.UUID
	HostID uuid.UUID
}
