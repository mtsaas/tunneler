{{- define "tunneler-exit.groupUser" -}}
tunneler:group-managed:{{ .Release.Namespace }}:{{ .Release.Name }}
{{- end -}}
