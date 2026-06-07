package iam

import (
	"encoding/json"
)

// UnmarshalJSON implements custom JSON unmarshaling for StringOrSlice
// which can be either a string or an array of strings in AWS IAM Policy JSON
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	// Try string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrSlice{str}
		return nil
	}

	// Try array of strings
	var slice []string
	if err := json.Unmarshal(data, &slice); err != nil {
		return err
	}
	*s = StringOrSlice(slice)
	return nil
}

// MarshalJSON implements custom JSON marshaling for StringOrSlice
func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}
