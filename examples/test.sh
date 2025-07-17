#!/bin/bash

clear
set -e

TD=$(mktemp -d XXXXXXXXXX)

# Change the range values to test more or less signatures
for i in {1..10}
do
    head -c 10 /dev/urandom > "$TD/message$i.msg"
done

declare -a schemes=("SLH-DSA-MTL-SHAKE-128S"
                    "SLH-DSA-MTL-SHAKE-128F"
                    "SLH-DSA-MTL-SHAKE-192S"
                    "SLH-DSA-MTL-SHAKE-192F"
                    "SLH-DSA-MTL-SHAKE-256S"
                    "SLH-DSA-MTL-SHAKE-256F" 
                    "SLH-DSA-MTL-SHA2-128S" 
                    "SLH-DSA-MTL-SHA2-128F"
                    "SLH-DSA-MTL-SHA2-192S"
                    "SLH-DSA-MTL-SHA2-192F" 
                    "SLH-DSA-MTL-SHA2-256S" 
                    "SLH-DSA-MTL-SHA2-256F")

FL=$(find . -type f -name "*.msg" -print0 | xargs -0 printf "%s ")

###################################################################
# Test the keygen, sign, and verify tools in binary string format
###################################################################
for i in "${schemes[@]}"
do
    rm -rf $TD/testkey.key
    KG=$( TIMEFORMAT="%R"; { time ( ./mtlkeygen $TD/testkey.key "$i" > $TD/keygen.output.shell ); } 2>&1 ) 
    PK=$( cat $TD/keygen.output.shell | cut -d "," -f 3)

    SM=$( TIMEFORMAT="%R"; { time ( ./mtlsign -l $TD/testkey.key $FL > $TD/sign.output.shell ); } 2>&1 ) 
    grep "Ladder," $TD/sign.output.shell | cut -d "," -f 3 | xxd -r -p > $TD/verify.ladder

    SIGNATURES=0
    VM=0
    VMT=0
    FAILURES=0
    while IFS=',' read -r message leaf authpath; do
        if [[ "$leaf" != "" ]]; then
            VMT=$( TIMEFORMAT="%R"; { time ( ./mtlverify -q $i $PK $(cat $message | xxd -p) $authpath -l $TD/verify.ladder > $TD/verify.output.shell ); } 2>&1 ) 
            if [ $? -ne 0 ]; then
                ((FAILURES++))
                echo "!!!! ERROR - Verification Error on $leaf for scheme $i"
            fi                
            VM=$(echo "$VM + $VMT" | bc)
            SIGNATURES=$((SIGNATURES + 1))            
        fi
    done < $TD/sign.output.shell

    RECORDS=$(find $TD/ -mindepth 1 -type f -name "*.msg" -printf x | wc -c)

    echo "  Scheme $i"
    echo "    Records Signed        = $RECORDS messages"
    echo "    Records Verified      = $SIGNATURES messages"
    echo "    Signatures Failed     = $FAILURES signatures"
    echo "    Key Generation Time   = $(echo $KG | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    Record Signing Time   = $(echo $SM | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    All Verification Time = $(echo $VM | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "  "

done


###################################################################
# Test the keygen, sign, and verify tools in base64 string format
###################################################################
# Change the range values to test more or less signatures
for F in $FL
do
    cat $F | base64 -w 0 > $TD/tmp.file
    mv $TD/tmp.file $F
done

for i in "${schemes[@]}"
do
    rm -rf $TD/testkey.key
    KG=$( TIMEFORMAT="%R"; { time ( ./mtlkeygen $TD/testkey.key "$i" > $TD/keygen.output.shell ); } 2>&1 ) 
    PK=$( cat $TD/keygen.output.shell | cut -d "," -f 3)

    SM=$( TIMEFORMAT="%R"; { time ( ./mtlsign -b -l $TD/testkey.key $FL > $TD/sign.output.shell ); } 2>&1 ) 
    rm -rf $TD/verify.b64.ladder > /dev/null 
    grep "Ladder," $TD/sign.output.shell | sed 's/Ladder,,//g' > $TD/verify.b64.ladder

    SIGNATURES=0
    VM=0
    VMT=0
    FAILURES=0
    while IFS=',' read -r message leaf authpath binpath; do
        if [[ "$leaf" != "" ]]; then
            VMT=$( TIMEFORMAT="%R"; { time ( ./mtlverify -b -q $i $(echo $PK | xxd -r -p | base64 -w 0) $(cat $message ) $authpath -l $TD/verify.b64.ladder > $TD/verify.output.shell ); } 2>&1 ) 
            if [ $? -ne 0 ]; then
                ((FAILURES++))
                echo "!!!! ERROR - Verification Error on $leaf for scheme $i"
            fi
            VM=$(echo "$VM + $VMT" | bc)
            SIGNATURES=$((SIGNATURES + 1))            
        fi
    done < $TD/sign.output.shell

    RECORDS=$(find $TD/ -mindepth 1 -type f -name "*.msg" -printf x | wc -c)

    echo "  Scheme $i (Base64 Inputs)"
    echo "    Records Signed        = $RECORDS messages"
    echo "    Records Verified      = $SIGNATURES messages"
    echo "    Signatures Failed     = $FAILURES signatures"
    echo "    Key Generation Time   = $(echo $KG | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    Record Signing Time   = $(echo $SM | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    All Verification Time = $(echo $VM | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "  "

done

rm -rf $TD
