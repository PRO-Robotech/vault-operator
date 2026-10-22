#!/usr/bin/env bash
# check-verifier vo21 round 2: injections on 5d5faca. Exit code is not the verdict; the log is.
set -u
cd "$(git rev-parse --show-toplevel)"
export KUBEBUILDER_ASSETS="$(cd "$KUBEBUILDER_ASSETS" && pwd)"
echo "HEAD $(git rev-parse HEAD) KUBEBUILDER_ASSETS=$KUBEBUILDER_ASSETS"; ls "$KUBEBUILDER_ASSETS"
PKG=./internal/controller
UNIT='^(TestApplyPoliciesConditionNamesWhyTheRulesDoNotRender|TestRenderClaimPolicy.*|TestMaxRulesLengthIsTheOneInTheCRD|TestCV21b.*|TestControllers)$'
FOCUS='VaultClaim rules that do not render|CV21b render refusal|rules (at|past) the length limit'
filt(){ grep -avE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]*\s+(INFO|DEBUG|ERROR)\s' ; }
probe(){ # name
  local out=".cv21/out-$1.txt"
  timeout 420 go test -tags cv21 -count=1 -timeout 300s -v -run "$UNIT" $PKG -args -ginkgo.focus="$FOCUS" -ginkgo.v > "$out" 2>&1
  local rc=$?
  filt < "$out"
  echo "SUMMARY $1 rc=$rc pass=$(grep -ac -- '^--- PASS' "$out") fail=$(grep -ac -- '^--- FAIL' "$out") subfail=$(grep -acE -- '^\s+--- FAIL' "$out") ginkgo=[$(grep -aE '^Ran [0-9]+ of [0-9]+ Specs' "$out" | head -1)] [$(grep -aE '^(SUCCESS|FAIL)! ' "$out" | head -1)]"
  grep -aE '^\s*(--- FAIL|\[FAIL\])' "$out" | sed "s/^/FAILLINE $1: /" | head -40
}
echo "::group::CENSUS head tree, make test set, no cv21 tag"
go test -count=1 -json $(go list ./... | grep -v /e2e) > .cv21/census.json 2>.cv21/census.err; echo "census rc=$?"
for a in pass fail skip; do
  echo "top-level $a: $(jq -r --arg a $a 'select(.Action==$a and .Test!=null and (.Test|contains("/")|not)) | .Test' .cv21/census.json | wc -l)  with-subtests $a: $(jq -r --arg a $a 'select(.Action==$a and .Test!=null) | .Test' .cv21/census.json | wc -l)"
done
jq -r 'select(.Action=="fail" and .Test!=null) | "CENSUS-FAIL \(.Package) \(.Test)"' .cv21/census.json
jq -r 'select(.Action=="pass" and .Test!=null) | .Test' .cv21/census.json | grep -E '^(TestApplyPoliciesConditionNamesWhyTheRulesDoNotRender|TestRenderClaimPolicy(RefusesALoop|AdmitsOnly|RefusesRulesLonger|BoundsTheRendered)|TestMaxRulesLength|TestControllers)' | sort -u | sed 's/^/CENSUS-PASS /'
jq -r 'select(.Action=="output" and .Test=="TestControllers") | .Output' .cv21/census.json | grep -aE 'Ran [0-9]+ of|SUCCESS!|FAIL!' | head
cat .cv21/census.err | tail -5
echo "::endgroup::"
echo "::group::C0 control, no injection (want green)"; probe C0; echo "::endgroup::"
for i in I1 I2 I3 I4 I5 I6 N1 N2 N3 N4 N5 N6 N7 N8; do
  echo "::group::$i injection (want red where it bears)"
  if git apply ".cv21/$i.patch"; then git diff --stat; probe "$i"; else echo "APPLY-FAIL $i"; fi
  git checkout -- internal config api; echo "clean after $i: $(git status --porcelain --untracked-files=no | wc -l)"
  echo "::endgroup::"
done
exit 0
