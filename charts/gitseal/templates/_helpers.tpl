{{- define "gitseal.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gitseal.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (include "gitseal.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "gitseal.broker.name" -}}sealdbroker{{- end -}}
{{- define "gitseal.controller.name" -}}gitseal-controller{{- end -}}

{{- define "gitseal.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: gitseal
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
{{- end -}}

{{- define "gitseal.broker.image" -}}
{{- $tag := .Values.broker.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.broker.image.repository $tag -}}
{{- end -}}
