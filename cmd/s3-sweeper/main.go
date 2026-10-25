/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Команда s3-sweeper — каркас красной пробы.
package main

import (
	"context"
	"io"
	"net/http"
	"os"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stderr, nil))
}

func run(context.Context, []string, func(string) string, io.Writer, *http.Client) int { return 0 }
