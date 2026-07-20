/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"fmt"
	"regexp"
	"strings"
)

const bucketMaxLen = 63

var bucketInvalid = regexp.MustCompile(`[^a-z0-9-]+`)

// bucketBaseName derives "k8s-<custLogin>-<clusterName>".
func bucketBaseName(custLogin, clusterName string) string {
	name := "k8s-" + sanitizeBucketPart(custLogin) + "-" + sanitizeBucketPart(clusterName)
	if len(name) > bucketMaxLen {
		name = strings.TrimRight(name[:bucketMaxLen], "-")
	}
	return name
}

// sanitizeBucketPart lowercases and normalises to [a-z0-9-] without runs of '-'.
func sanitizeBucketPart(s string) string {
	s = strings.ToLower(s)
	s = bucketInvalid.ReplaceAllString(s, "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

// s3EndpointForRegion returns the per-region S3 endpoint; empty defaults to ru1.
func s3EndpointForRegion(region string) string {
	if region == "" {
		region = "ru1"
	}
	return fmt.Sprintf("https://s3.%s.storage.beget.cloud", region)
}
