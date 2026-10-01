{{- define "tunneler-coordinator.validateSharingIngress" -}}
{{- if and .Values.config.sharing .Values.ingress.enabled -}}
{{- if not (has .Values.ingress.host .Values.config.sharing.control_hosts) -}}
{{- fail "ingress.host must appear in config.sharing.control_hosts when sharing and ingress are enabled" -}}
{{- end -}}
{{- end -}}
{{- end -}}
