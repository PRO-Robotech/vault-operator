/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package ci judges the GitHub workflows of the repository. Branch protection
// names required checks by job name, so two jobs of one name are one check
// to it, and a check a pull request never runs blocks every pull request.
package ci

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const workflowDir = "../../.github/workflows"

type workflow struct {
	// The YAML 1.1 reader takes an unquoted on: for a boolean, so the
	// triggers arrive under "true"; a quoted "on" arrives as written.
	On     any `json:"on"`
	OnBool any `json:"true"`
	Jobs   map[string]struct {
		Name  string `json:"name"`
		Steps []struct {
			Name string         `json:"name"`
			Uses string         `json:"uses"`
			If   string         `json:"if"`
			With map[string]any `json:"with"`
		} `json:"steps"`
	} `json:"jobs"`
}

func readWorkflows(t *testing.T) map[string]workflow {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(workflowDir, "*.yml"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	more, err := filepath.Glob(filepath.Join(workflowDir, "*.yaml"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	files = append(files, more...)
	out := make(map[string]workflow, len(files))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var w workflow
		if err := yaml.Unmarshal(raw, &w); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		out[filepath.Base(f)] = w
	}
	// A walk that read nothing judges nothing.
	if len(out) == 0 {
		t.Fatalf("no workflow read under %s", workflowDir)
	}
	return out
}

// checkName is the name GitHub gives the check run of a job.
func checkName(id, name string) string {
	if name != "" {
		return name
	}
	return id
}

// Every job is its own check: branch protection can require each one.
func TestEveryJobHasACheckNameOfItsOwn(t *testing.T) {
	seen := map[string][]string{}
	jobs := 0
	for file, w := range readWorkflows(t) {
		for id, j := range w.Jobs {
			jobs++
			n := checkName(id, j.Name)
			seen[n] = append(seen[n], file+":"+id)
		}
	}
	if jobs == 0 {
		t.Fatal("no job read in any workflow")
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if len(seen[n]) > 1 {
			sort.Strings(seen[n])
			t.Errorf("check %q is run by %d jobs: %v", n, len(seen[n]), seen[n])
		}
	}
	t.Logf("workflows read; jobs=%d checks=%d: %v", jobs, len(names), names)
}

// The image build is a check of every pull request; only a push publishes.
func TestImageBuildRunsOnPullRequestAndPushesOnlyOnPush(t *testing.T) {
	w, ok := readWorkflows(t)["docker-build.yml"]
	if !ok {
		t.Fatal("docker-build.yml not read")
	}
	triggers := triggersOf(w)
	if len(triggers) == 0 {
		t.Fatal("docker-build.yml: no trigger read")
	}
	if !triggers["pull_request"] {
		t.Errorf("docker-build.yml does not run on pull_request: triggers %v", triggers)
	}
	builds, logins := 0, 0
	for id, j := range w.Jobs {
		for _, s := range j.Steps {
			switch {
			case strings.HasPrefix(s.Uses, "docker/build-push-action@"):
				builds++
				if got := s.With["push"]; got != "${{ github.event_name == 'push' }}" {
					t.Errorf("%s step %q: push = %v, want ${{ github.event_name == 'push' }}", id, s.Name, got)
				}
			case strings.HasPrefix(s.Uses, "docker/login-action@"):
				logins++
				if s.If != "github.event_name == 'push'" {
					t.Errorf("%s step %q: if = %q, want github.event_name == 'push'", id, s.Name, s.If)
				}
			}
		}
	}
	if builds == 0 || logins == 0 {
		t.Fatalf("docker-build.yml: build steps %d, login steps %d; both must be read", builds, logins)
	}
	t.Logf("docker-build.yml: build steps %d, login steps %d", builds, logins)
}

// triggersOf is the set of events a workflow runs on, in each form "on"
// may take: an event name, a list of them, or a map keyed by them.
func triggersOf(w workflow) map[string]bool {
	out := map[string]bool{}
	for _, on := range []any{w.On, w.OnBool} {
		switch v := on.(type) {
		case string:
			out[v] = true
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out[s] = true
				}
			}
		case map[string]any:
			for k := range v {
				out[k] = true
			}
		}
	}
	return out
}

// Каждый Dockerfile корня собирается заданием docker-build.yml и публикуется
// под своим именем образа; двойник cloud-manager (Dockerfile.cmfake) — среди
// них: образ стенда даёт сборка, а не рука.
func TestEveryDockerfileIsBuiltByTheImageWorkflow(t *testing.T) {
	w, ok := readWorkflows(t)["docker-build.yml"]
	if !ok {
		t.Fatal("docker-build.yml not read")
	}
	built := map[string]string{}
	for _, j := range w.Jobs {
		for _, s := range j.Steps {
			if !strings.HasPrefix(s.Uses, "docker/build-push-action@") {
				continue
			}
			file, _ := s.With["file"].(string)
			tags, _ := s.With["tags"].(string)
			built[strings.TrimPrefix(file, "./")] = tags
		}
	}
	files, err := filepath.Glob("../../Dockerfile*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	read := 0
	for _, f := range files {
		name := filepath.Base(f)
		if strings.HasSuffix(name, ".cross") {
			continue
		}
		read++
		if _, ok := built[name]; !ok {
			t.Errorf("%s is not built by docker-build.yml (built: %v)", name, built)
		}
	}
	if read == 0 {
		t.Fatal("no Dockerfile read")
	}
	tags, ok := built["Dockerfile.cmfake"]
	if !ok {
		t.Fatalf("Dockerfile.cmfake is not built by docker-build.yml (built: %v)", built)
	}
	if !strings.Contains(tags, "/cmfake:${{ steps.sanitize.outputs.branch }}-${{ steps.short-sha.outputs.sha }}") {
		t.Fatalf("Dockerfile.cmfake tags = %q, want <namespace>/cmfake:<branch>-<sha8>", tags)
	}
	t.Logf("Dockerfiles read %d, build steps %d", read, len(built))
}

// Уборщик бакетов CI (Dockerfile.s3-sweeper) публикуется под своим именем
// образа той же схемой тега: задание CI берёт его по имени ветки и sha.
func TestTheS3SweeperImageIsPublishedUnderItsName(t *testing.T) {
	w, ok := readWorkflows(t)["docker-build.yml"]
	if !ok {
		t.Fatal("docker-build.yml not read")
	}
	steps := 0
	for _, j := range w.Jobs {
		for _, s := range j.Steps {
			if !strings.HasPrefix(s.Uses, "docker/build-push-action@") {
				continue
			}
			steps++
			if file, _ := s.With["file"].(string); strings.TrimPrefix(file, "./") != "Dockerfile.s3-sweeper" {
				continue
			}
			tags, _ := s.With["tags"].(string)
			if !strings.Contains(tags, "/s3-sweeper:${{ steps.sanitize.outputs.branch }}-${{ steps.short-sha.outputs.sha }}") {
				t.Fatalf("Dockerfile.s3-sweeper tags = %q, want <namespace>/s3-sweeper:<branch>-<sha8>", tags)
			}
			if push, _ := s.With["push"].(string); push != "${{ github.event_name == 'push' }}" {
				t.Fatalf("Dockerfile.s3-sweeper push = %q, want pushes only on push events", push)
			}
			return
		}
	}
	t.Fatalf("Dockerfile.s3-sweeper is not built by docker-build.yml (build steps read %d)", steps)
}
