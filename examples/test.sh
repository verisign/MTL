#!/bin/bash

clear
set -e

mkdir -p tmp

# Change the range values to test more or less signatures
for i in {1..10}
do
    head -c 10 /dev/urandom > "tmp/message$i.msg"
done

declare -a schemes=("SPHINCS+-MTL-SHAKE-128S-SIMPLE"
                    "SPHINCS+-MTL-SHAKE-128F-SIMPLE"
                    "SPHINCS+-MTL-SHAKE-192S-SIMPLE"
                    "SPHINCS+-MTL-SHAKE-192F-SIMPLE"
                    "SPHINCS+-MTL-SHAKE-256S-SIMPLE"
                    "SPHINCS+-MTL-SHAKE-256F-SIMPLE" 
                    "SPHINCS+-MTL-SHA2-128S-SIMPLE" 
                    "SPHINCS+-MTL-SHA2-128F-SIMPLE"
                    "SPHINCS+-MTL-SHA2-192S-SIMPLE"
                    "SPHINCS+-MTL-SHA2-192F-SIMPLE" 
                    "SPHINCS+-MTL-SHA2-256S-SIMPLE" 
                    "SPHINCS+-MTL-SHA2-256F-SIMPLE")

FL=$(find . -type f -name "*.msg" -print0 | xargs -0 printf "%s ")

###################################################################
# Test the keygen, sign, and verify tools in binary string format
###################################################################
for i in "${schemes[@]}"
do
    rm -rf tmp/testkey.key
    KG=$( TIMEFORMAT="%R"; { time ( ./mtlkeygen tmp/testkey.key "$i" > tmp/keygen.output.shell ); } 2>&1 ) 
    PK=$( cat tmp/keygen.output.shell | cut -d "," -f 3)

    SM=$( TIMEFORMAT="%R"; { time ( ./mtlsign -l tmp/testkey.key $FL > tmp/sign.output.shell ); } 2>&1 ) 
    grep "Ladder," tmp/sign.output.shell | cut -d "," -f 3 | xxd -r -p > tmp/verify.ladder

    SIGNATURES=0
    VM=0
    VMT=0
    FAILURES=0
    while IFS=',' read -r message leaf authpath; do
        if [[ "$leaf" != "" ]]; then
            VMT=$( TIMEFORMAT="%R"; { time ( ./mtlverify -q $i $PK $(cat $message | xxd -p) $authpath -l tmp/verify.ladder > tmp/verify.output.shell ); } 2>&1 ) 
            if [ $? -ne 0 ]; then
                ((FAILURES++))
                echo "!!!! ERROR - Verification Error on $leaf for scheme $i"
            fi                
            VM=$(echo "$VM + $VMT" | bc)
            SIGNATURES=$((SIGNATURES + 1))            
        fi
    done < tmp/sign.output.shell

    RECORDS=$(find tmp/ -mindepth 1 -type f -name "*.msg" -printf x | wc -c)

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
    cat $F | base64 -w 0 > tmp/tmp.file
    mv tmp/tmp.file $F
done

for i in "${schemes[@]}"
do
    rm -rf tmp/testkey.key
    KG=$( TIMEFORMAT="%R"; { time ( ./mtlkeygen tmp/testkey.key "$i" > tmp/keygen.output.shell ); } 2>&1 ) 
    PK=$( cat tmp/keygen.output.shell | cut -d "," -f 3)

    SM=$( TIMEFORMAT="%R"; { time ( ./mtlsign -b -l tmp/testkey.key $FL > tmp/sign.output.shell ); } 2>&1 ) 
    rm -rf tmp/verify.b64.ladder > /dev/null 
    grep "Ladder," tmp/sign.output.shell | sed 's/Ladder,,//g' > tmp/verify.b64.ladder

    SIGNATURES=0
    VM=0
    VMT=0
    FAILURES=0
    while IFS=',' read -r message leaf authpath binpath; do
        if [[ "$leaf" != "" ]]; then
            VMT=$( TIMEFORMAT="%R"; { time ( ./mtlverify -b -q $i $(echo $PK | xxd -r -p | base64 -w 0) $(cat $message ) $authpath -l tmp/verify.b64.ladder > tmp/verify.output.shell ); } 2>&1 ) 
            if [ $? -ne 0 ]; then
                ((FAILURES++))
                echo "!!!! ERROR - Verification Error on $leaf for scheme $i"
            fi
            VM=$(echo "$VM + $VMT" | bc)
            SIGNATURES=$((SIGNATURES + 1))            
        fi
    done < tmp/sign.output.shell

    RECORDS=$(find tmp/ -mindepth 1 -type f -name "*.msg" -printf x | wc -c)

    echo "  Scheme $i (Base64 Inputs)"
    echo "    Records Signed        = $RECORDS messages"
    echo "    Records Verified      = $SIGNATURES messages"
    echo "    Signatures Failed     = $FAILURES signatures"
    echo "    Key Generation Time   = $(echo $KG | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    Record Signing Time   = $(echo $SM | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    All Verification Time = $(echo $VM | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "  "

done

rm -rf tmp
