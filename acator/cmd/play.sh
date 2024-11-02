#!/bin/bash

url=${FCLI_URL:-"http://localhost:3000"}
lvl=${lvl:-"-v=0"}
glb=${glb:-""} # globals like -err2-trace, ...

go run main.go \
	$lvl \
	$glb \
 \
	auth -url "$url" \
 \
	-log-begin-met 'POST' \
	-log-begin '%s/assertion/options' \
	-log-finish '%s/assertion/result' \
	-log-begin-pl '{"username":"%s"}' \
	-log-begin-pl-middle '{"publicKey": %s}' \
 \
	-reg-begin-met 'POST' \
	-reg-begin '%s/attestation/options' \
	-reg-finish '%s/attestation/result' \
	-reg-begin-pl '{"username":"%s"}' \
	-reg-begin-pl-middle '{"publicKey": %s}' \
	$@
