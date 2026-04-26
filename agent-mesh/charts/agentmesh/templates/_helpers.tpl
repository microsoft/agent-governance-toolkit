{{/*
Expand the name of the chart.
*/}}
{{- define "agentmesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "agentmesh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "agentmesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "agentmesh.labels" -}}
helm.sh/chart: {{ include "agentmesh.chart" . }}
{{ include "agentmesh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "agentmesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentmesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component labels — adds app.kubernetes.io/component
*/}}
{{- define "agentmesh.componentLabels" -}}
{{ include "agentmesh.labels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component selector labels
*/}}
{{- define "agentmesh.componentSelectorLabels" -}}
{{ include "agentmesh.selectorLabels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "agentmesh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "agentmesh.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Prometheus scrape annotations
*/}}
{{- define "agentmesh.prometheusAnnotations" -}}
{{- if .Values.monitoring.prometheus.enabled }}
prometheus.io/scrape: "true"
prometheus.io/port: {{ .metricsPort | quote }}
prometheus.io/path: "/metrics"
{{- end }}
{{- end }}

{{/*
Resolve image tag — falls back to global.imageTag then Chart.AppVersion
*/}}
{{- define "agentmesh.imageTag" -}}
{{- . | default $.Values.global.imageTag | default $.Chart.AppVersion }}
{{- end }}
