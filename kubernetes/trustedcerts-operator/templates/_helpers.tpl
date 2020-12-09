{{/*
Get an image prefix
*/}}
{{- define "image-prefix" -}}
{{- if .imagesHost -}}
{{- printf "%s/" .imagesHost -}}
{{- else -}}
{{- printf "" -}}
{{- end -}}
{{- end -}}

{{/*
Helper function to get the proper image tag
*/}}
{{- define "image-tag" -}}
{{- default "latest" .Chart.AppVersion -}}
{{- end -}}