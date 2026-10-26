#!/usr/bin/env bash
# check-images.sh — every Dockerfile stage is pinned by digest, and the Go
# builder image runs the same Go version as go.mod. Prints what it read; a
# walk that finds no FROM line fails (nothing read is not a pass).
set -euo pipefail

root="${1:-.}"
gomod_version="$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")"
if [[ -z "$gomod_version" ]]; then
	echo "check-images: no go directive in $root/go.mod" >&2
	exit 1
fi

files=0
stages=0
bad=0
shopt -s nullglob
for f in "$root"/Dockerfile "$root"/Dockerfile.*; do
	[[ -f "$f" ]] || continue
	[[ "$f" == *.cross ]] && continue
	files=$((files + 1))
	while IFS= read -r line; do
		stages=$((stages + 1))
		image="$(awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; exit } }' <<<"$line")"
		if [[ "$image" != *@sha256:* ]]; then
			echo "check-images: $f: not pinned by digest: $line" >&2
			bad=$((bad + 1))
		fi
		if [[ "$image" == golang:* ]]; then
			tag="${image#golang:}"
			tag="${tag%%@*}"
			if [[ "$tag" != "$gomod_version" ]]; then
				echo "check-images: $f: golang:$tag differs from go.mod go $gomod_version" >&2
				bad=$((bad + 1))
			fi
		fi
	done < <(grep -E '^[[:space:]]*FROM[[:space:]]' "$f")
done

echo "check-images: read $files Dockerfiles, $stages FROM lines, go.mod go $gomod_version, findings $bad"
if [[ "$stages" -eq 0 ]]; then
	echo "check-images: no FROM line read" >&2
	exit 1
fi
[[ "$bad" -eq 0 ]]
