/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package privacyca

import (
	model "github.com/intel-secl/intel-secl/v4/pkg/model/ta"
	"github.com/pkg/errors"
)

func NewPrivacyCA(request model.IdentityRequest) (PrivacyCa, error) {
	log.Trace("privacyca:NewPrivacyCA() Entering")
	defer log.Trace("privacyca:NewPrivacyCA() Leaving")

	switch request.TpmVersion {
	case "2.0":
		return &PrivacyCATpm2{}, nil
	default:
		return nil, errors.New("privacyca:NewPrivacyCA() Unsupported tpm version")
	}
}
