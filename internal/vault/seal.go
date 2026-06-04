/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"context"
	"net/http"
)

type SealStatus struct {
	Sealed      bool   `json:"sealed"`
	Initialized bool   `json:"initialized"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
}

// SealStatus calls GET /v1/sys/seal-status. The endpoint is reachable even
// when Vault is sealed or uninitialized and returns 200 in those states —
// only transport errors yield a non-nil error here. Callers must inspect
// Sealed / Initialized to decide whether Login is possible.
func (c *Client) SealStatus(ctx context.Context) (*SealStatus, error) {
	resp, err := c.Do(ctx, &Request{
		Method:       http.MethodGet,
		Path:         "sys/seal-status",
		AuthOptional: true,
	})
	if err != nil {
		return nil, err
	}
	var ss SealStatus
	if err := resp.Decode(&ss); err != nil {
		return nil, err
	}
	return &ss, nil
}
