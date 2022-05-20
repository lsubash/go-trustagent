/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v4/pkg/model/hvs"
	"time"
)

type HVSReport struct {
	ID          uuid.UUID
	HostID      uuid.UUID
	TrustReport hvs.TrustReport
	CreatedAt   time.Time
	Expiration  time.Time
	// Saml is string which is actually xml encoded to string
	Saml string
}
