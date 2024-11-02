#!/bin/bash

# ===== login ======
read -r -d '' logBegJSON << EOF
{"username":"%s",
"user_verification":"discouraged"}
EOF

read -r -d '' logFinJSON << EOF
{"username":"%s",
"response": %s}
EOF

read -r -d '' logBegInputJSON << EOF
{"username":"%s",
"response": %s }
EOF

read -r -d '' logBegMiddleJSON << EOF
{"publicKey": %s}
EOF

# ===== registration ======
read -r -d '' regBegJSON << EOF
{"username":"%s",
"algorithms":["es256"],
"user_verification": "preferred",
"attestation": "direct",
"attachment": "cross_platform",
"discoverable_credential": "preferred"}
EOF

read -r -d '' regFinJSON << EOF
{"username":"%s",
"response": %s}
EOF

read -r -d '' regBegInputJSON << EOF
{"username":"%s",
"response": %s }
EOF

read -r -d '' regBegMiddleJSON << EOF
{"publicKey": %s}
EOF

# these follow FIDO2 reference document
if [[ "$FIDO_ENDPOINTS" != "" ]]; then
	log_begin_met='POST'
	log_begin='%s/assertion/options'
	log_finish='%s/assertion/result'
	reg_begin_met='POST'
	reg_begin='%s/attestation/options'
	reg_finish='%s/attestation/result'
else # these are for webauthn.io
	log_begin_met='POST'
	log_begin='%s/authentication/options'
	log_finish='%s/authentication/verification'
	reg_begin_met='POST'
	reg_begin='%s/registration/options'
	reg_finish='%s/registration/verification'
fi

url=${FCLI_URL:-"https://webauthn.io"}
lvl=${lvl:-"-v=0"} # e.g. -v=5, when 5<= payloads are echoed
glb=${glb:-""} # globals like -err2-trace, ...

go run main.go \
	$lvl \
	$glb \
 \
	auth -url "$url" \
	-log-begin-met "$log_begin_met" \
	-log-begin "$log_begin" \
	-log-finish "$log_finish" \
 \
	-reg-begin-met "$reg_begin_met" \
	-reg-begin "$reg_begin" \
	-reg-finish "$reg_finish" \
 \
	-log-begin-pl "$logBegJSON" \
	-log-begin-pl-in "$logBegInputJSON" \
	-log-begin-pl-middle "$logBegMiddleJSON" \
	-log-finish-pl "$logFinJSON" \
 \
	-reg-begin-pl "$regBegJSON" \
	-reg-begin-pl-in "$regBegInputJSON" \
	-reg-begin-pl-middle "$regBegMiddleJSON" \
	-reg-finish-pl "$regFinJSON" \
	$@
