{{/* Chart name (respects nameOverride). */}}
{{- define "purser.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully-qualified release name (respects fullnameOverride). */}}
{{- define "purser.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "purser.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "purser.labels" -}}
helm.sh/chart: {{ include "purser.chart" . }}
{{ include "purser.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: purser
{{- end -}}

{{/* Selector labels (immutable across upgrades). */}}
{{- define "purser.selectorLabels" -}}
app.kubernetes.io/name: {{ include "purser.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "purser.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "purser.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Resolve an image "repo:tag" using AppVersion as the default tag. */}}
{{- define "purser.image" -}}
{{- $repo := .repo -}}
{{- $tag := .tag | default .root.Chart.AppVersion -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}

{{/* Name of the Secret holding the API key (existing or chart-created). */}}
{{- define "purser.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "purser.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* API key for the chart-created Secret: explicit value, else the current
     value already in the cluster (retained across upgrades), else a fresh
     random key. Only used when auth.existingSecret is empty. */}}
{{- define "purser.apiKey" -}}
{{- if .Values.auth.apiKey -}}
{{- .Values.auth.apiKey -}}
{{- else -}}
{{- $sec := lookup "v1" "Secret" .Release.Namespace (include "purser.authSecretName" .) -}}
{{- if and $sec $sec.data (index $sec.data .Values.auth.secretKey) -}}
{{- index $sec.data .Values.auth.secretKey | b64dec -}}
{{- else -}}
{{- randAlphaNum 40 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Pod annotations incl. Prometheus scrape discovery. */}}
{{- define "purser.podAnnotations" -}}
{{- $ann := deepCopy .Values.podAnnotations -}}
{{- if and .Values.metrics.enabled .Values.metrics.podAnnotations -}}
{{- $_ := set $ann "prometheus.io/scrape" "true" -}}
{{- $_ := set $ann "prometheus.io/port" "8080" -}}
{{- $_ := set $ann "prometheus.io/path" "/metrics" -}}
{{- end -}}
{{- toYaml $ann -}}
{{- end -}}

{{/* Common PURSER_* env shared by core, hf and deep workloads. */}}
{{- define "purser.commonEnv" -}}
- name: PURSER_POLICY
  value: /policies/policy.yaml
- name: PURSER_SCAN_ROOT
  value: {{ .Values.config.scanRoot | quote }}
- name: PURSER_MAX_UPLOAD_MB
  value: {{ .Values.config.maxUploadMB | quote }}
- name: PURSER_MAX_SCAN_MB
  value: {{ .Values.config.maxScanMB | quote }}
- name: PURSER_MAX_CONCURRENT_SCANS
  value: {{ .Values.config.maxConcurrentScans | quote }}
- name: PURSER_RATE_LIMIT_RPM
  value: {{ .Values.config.rateLimitRpm | quote }}
- name: PURSER_MAX_FINDINGS_PER_FILE
  value: {{ .Values.config.maxFindingsPerFile | quote }}
- name: PURSER_METRICS_ENABLED
  value: {{ ternary "1" "0" .Values.metrics.enabled | quote }}
- name: PURSER_AUDIT
  value: {{ .Values.audit.mode | quote }}
- name: PURSER_SYSLOG_ADDRESS
  value: {{ .Values.audit.syslogAddress | quote }}
- name: PURSER_SYSLOG_FACILITY
  value: {{ .Values.audit.syslogFacility | quote }}
{{- if .Values.policy.origins }}
- name: PURSER_ORIGINS
  value: /policies/origins.yaml
{{- end }}
{{- if .Values.auth.enabled }}
- name: PURSER_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "purser.authSecretName" . }}
      key: {{ .Values.auth.secretKey }}
{{- end }}
{{- with .Values.config.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}
