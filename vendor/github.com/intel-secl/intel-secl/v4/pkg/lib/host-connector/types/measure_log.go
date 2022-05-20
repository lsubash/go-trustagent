/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package types

type MeasureLog struct {
	Pcr       Pcr        `json:"pcr"`
	TpmEvents []EventLog `json:"tpm_events"`
}
