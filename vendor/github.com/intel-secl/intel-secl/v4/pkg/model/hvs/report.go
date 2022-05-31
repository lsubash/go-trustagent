/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"time"

	"github.com/google/uuid"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
)

type ReportCollection struct {
	Reports []*Report `json:"reports" xml:"reports"`
}

type Report struct {
	// swagger:strfmt uuid
	ID               uuid.UUID        `json:"id"`
	TrustInformation TrustInformation `json:"trust_information"`
	// swagger:strfmt uuid
	HostID      uuid.UUID        `json:"host_id"`
	TrustReport TrustReport      `json:"-"`
	Saml        string           `json:"-"`
	HostInfo    taModel.HostInfo `json:"host_info"`
	CreatedAt   time.Time        `json:"created"`
	Expiration  time.Time        `json:"expiration"`
}

type TrustInformation struct {
	Overall     bool                                 `json:"OVERALL"`
	FlavorTrust map[FlavorPartName]FlavorTrustStatus `json:"flavors_trust"`
}

type FlavorTrustStatus struct {
	Trust                bool         `json:"trust"`
	RuleResultCollection []RuleResult `json:"rules"`
}

type ReportCreateRequest struct {
	// swagger:strfmt uuid
	HostID uuid.UUID `json:"host_id"`
	// swagger:strfmt uuid
	HardwareUUID uuid.UUID `json:"hardware_uuid"`
	HostName     string    `json:"host_name"`
}
