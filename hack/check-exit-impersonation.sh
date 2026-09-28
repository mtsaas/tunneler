#!/usr/bin/env bash
set -euo pipefail

chart=charts/tunneler-exit
rendered=$(helm template x "$chart" --values hack/kind/exit-values.yaml \
  --set kubernetes.users='{alice@example.com}')

# Check every impersonation rule, including any wildcard or extra rule added
# later. A resourceNames line in some other rule must not satisfy the test.
impersonation_rules=$(awk '
  /^---/ || /^  - apiGroups:/ {
    if (impersonate) print resource ":" names
    resource = names = impersonate = ""
  }
  /    resources:/ { resource = $0; sub(/^.*resources: /, "", resource) }
  /    verbs: \["impersonate"\]/ { impersonate = 1 }
  /    resourceNames:/ { names = $0; sub(/^.*resourceNames: /, "", names) }
  END { if (impersonate) print resource ":" names }
' <<<"$rendered")
expected_rules=$'["users"]:["alice@example.com"]\n["groups"]:["tunneler:view"]'
if [[ "$impersonation_rules" != "$expected_rules" ]]; then
  printf 'Unexpected impersonation rules:\n%s\n' "$impersonation_rules" >&2
  exit 1
fi

if out=$(helm template x "$chart" \
  --set server=https://example.com,cluster=ci,kubernetes.enabled=true,kubernetes.groups='{tunneler:view}' 2>&1); then
  echo 'the exit chart rendered kubernetes.enabled without kubernetes.users' >&2
  exit 1
fi
grep -Fq kubernetes.users <<<"$out"

if out=$(helm template x "$chart" \
  --set server=https://example.com,cluster=ci,kubernetes.enabled=true,kubernetes.groups='{tunneler:view}',kubernetes.users='{system:kube-controller-manager}' 2>&1); then
  echo 'the exit chart allowed a system: user' >&2
  exit 1
fi
grep -Fq 'system:' <<<"$out"
