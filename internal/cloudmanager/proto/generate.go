/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package cloudmanagerpb holds the hand-maintained minimal Go stubs for the
// cloud-manager internal S3/create contract. Regenerate after editing the .proto
// with: go generate ./internal/cloudmanager/proto/... (needs protoc,
// protoc-gen-go, protoc-gen-go-grpc on PATH).
package cloudmanagerpb

//go:generate protoc -I . --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative s3.proto cloud.proto
