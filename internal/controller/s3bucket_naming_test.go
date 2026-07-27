/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import "testing"

func TestBucketBaseName(t *testing.T) {
	cases := []struct {
		custLogin, cluster, want string
	}{
		{"dlputi1u", "ec8a00", "k8s-dlputi1u-ec8a00"},
		{"Cust_1", "EC8A00", "k8s-cust-1-ec8a00"},
		{"a__b", "c", "k8s-a-b-c"},
		{"-lead-", "clust", "k8s-lead-clust"},
	}
	for _, c := range cases {
		if got := bucketBaseName(c.custLogin, c.cluster); got != c.want {
			t.Errorf("bucketBaseName(%q,%q)=%q, want %q", c.custLogin, c.cluster, got, c.want)
		}
	}
}

func TestBucketBaseNameLength(t *testing.T) {
	got := bucketBaseName("verylongcustomerloginname0123456789", "clustername9876543210abcdef")
	if len(got) > bucketMaxLen {
		t.Errorf("name %q length %d exceeds %d", got, len(got), bucketMaxLen)
	}
	if got[len(got)-1] == '-' {
		t.Errorf("name %q must not end with '-'", got)
	}
}

func TestS3EndpointForRegion(t *testing.T) {
	if got := s3EndpointForRegion(""); got != "https://s3.ru1.storage.beget.cloud" {
		t.Errorf("empty region: got %q", got)
	}
	if got := s3EndpointForRegion("ru2"); got != "https://s3.ru2.storage.beget.cloud" {
		t.Errorf("ru2: got %q", got)
	}
}
