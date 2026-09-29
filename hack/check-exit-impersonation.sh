#!/usr/bin/env bash
set -euo pipefail

chart=charts/tunneler-exit
# Check every impersonation rule, including any wildcard or extra rule added
# later. A resourceNames line in some other rule must not satisfy the test.
impersonation_rules() {
  awk '
  /^---/ || /^  - apiGroups:/ {
    if (impersonate) print resource ":" names
    resource = names = impersonate = ""
  }
  /    resources:/ { resource = $0; sub(/^.*resources: /, "", resource) }
  /    verbs: \["impersonate"\]/ { impersonate = 1 }
  /    resourceNames:/ { names = $0; sub(/^.*resourceNames: /, "", names) }
  END { if (impersonate) print resource ":" names }
'
}

rendered=$(helm template x "$chart" --values hack/kind/exit-values.yaml \
  --set kubernetes.users='{alice@example.com}')
rules=$(impersonation_rules <<<"$rendered")
expected_rules=$'["users"]:["alice@example.com"]\n["groups"]:["tunneler:view"]'
if [[ "$rules" != "$expected_rules" ]]; then
  printf 'Unexpected impersonation rules:\n%s\n' "$rules" >&2
  exit 1
fi
if grep -Fq -- '--kubernetes-impersonate-user=' <<<"$rendered"; then
  echo 'the per-user chart unexpectedly selected group-managed impersonation' >&2
  exit 1
fi

group_rendered=$(helm template x "$chart" \
  --set server=https://example.com,cluster=ci,kubernetes.enabled=true,kubernetes.groups='{tunneler:view}')
group_rules=$(impersonation_rules <<<"$group_rendered")
expected_group_rules=$'["users"]:["tunneler:group-managed:default:x"]\n["groups"]:["tunneler:view"]'
if [[ "$group_rules" != "$expected_group_rules" ]]; then
  printf 'Unexpected group-managed impersonation rules:\n%s\n' "$group_rules" >&2
  exit 1
fi
grep -Fq -- '--kubernetes-impersonate-user=tunneler:group-managed:default:x' <<<"$group_rendered"

if out=$(helm template x "$chart" \
  --set server=https://example.com,cluster=ci,kubernetes.enabled=true,kubernetes.groups='{tunneler:view}',kubernetes.users='{system:kube-controller-manager}' 2>&1); then
  echo 'the exit chart allowed a system: user' >&2
  exit 1
fi
grep -Fq 'system:' <<<"$out"
