/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package serialize

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// SaveToJsonFile saves input object to given file path
func SaveToJsonFile(path string, obj interface{}) error {

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(obj)
}

// LoadFromJsonFile loads json file on given path to an output object
// example: LoadFromJsonFile(appStatePath, &AppStateStruct{})
func LoadFromJsonFile(path string, out interface{}) error {

	jsonFile, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonFile, out)
	if err != nil {
		return err
	}
	return nil
}
