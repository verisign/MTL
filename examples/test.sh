#!/bin/bash

clear
set -e

TD=$(mktemp -d XXXXXXXXXX)

# Change the range values to test more or less signatures
for i in {1..100}
do
    head -c 10 /dev/urandom > "$TD/message$i.msg"
done

declare -a schemes=("SLH-DSA-SHAKE-128s-MTL-SHAKE-128"
    "SLH-DSA-SHAKE-128f-MTL-SHAKE-128"
    "SLH-DSA-SHAKE-192s-MTL-SHAKE-192"
    "SLH-DSA-SHAKE-192f-MTL-SHAKE-192"
    "SLH-DSA-SHAKE-256s-MTL-SHAKE-256"
    "SLH-DSA-SHAKE-256f-MTL-SHAKE-256"
    "SLH-DSA-SHA2-128s-MTL-SHA2-128"
    "SLH-DSA-SHA2-128f-MTL-SHA2-128"
    "SLH-DSA-SHA2-192s-MTL-SHA2-192"
    "SLH-DSA-SHA2-192f-MTL-SHA2-192"
    "SLH-DSA-SHA2-256s-MTL-SHA2-256"
    "SLH-DSA-SHA2-256f-MTL-SHA2-256"
    "ML-DSA-44-MTL-SHAKE-128"
    "ML-DSA-65-MTL-SHAKE-192"
    "ML-DSA-87-MTL-SHAKE-256"
#    "Falcon-512-MTL-SHAKE-128"
    "Falcon-padded-512-MTL-SHAKE-128"
#    "Falcon-1024-MTL-SHAKE-256"
    "Falcon-padded-1024-MTL-SHAKE-256"
    "MAYO-1-MTL-SHAKE-128"
    "MAYO-2-MTL-SHAKE-128"
    "MAYO-3-MTL-SHAKE-192"
    "MAYO-5-MTL-SHAKE-256"
    "cross-rsdp-128-balanced-MTL-SHAKE-128"
    "cross-rsdp-128-fast-MTL-SHAKE-128"
    "cross-rsdp-128-small-MTL-SHAKE-128"
    "cross-rsdp-192-balanced-MTL-SHAKE-192"
    "cross-rsdp-192-fast-MTL-SHAKE-192"
    "cross-rsdp-192-small-MTL-SHAKE-192"
    "cross-rsdp-256-balanced-MTL-SHAKE-256"
    "cross-rsdp-256-fast-MTL-SHAKE-256"
    "cross-rsdp-256-small-MTL-SHAKE-256"
    "cross-rsdpg-128-balanced-MTL-SHAKE-128"
    "cross-rsdpg-128-fast-MTL-SHAKE-128"
    "cross-rsdpg-128-small-MTL-SHAKE-128"
    "cross-rsdpg-192-balanced-MTL-SHAKE-192"
    "cross-rsdpg-192-fast-MTL-SHAKE-192"
    "cross-rsdpg-192-small-MTL-SHAKE-192"
    "cross-rsdpg-256-balanced-MTL-SHAKE-256"
    "cross-rsdpg-256-fast-MTL-SHAKE-256"
    "cross-rsdpg-256-small-MTL-SHAKE-256"
    "OV-Is-MTL-SHAKE-128"
    "OV-Ip-MTL-SHAKE-128"
    "OV-III-MTL-SHAKE-192"
    "OV-V-MTL-SHAKE-256"
    "OV-Is-pkc-MTL-SHAKE-128"
    "OV-Ip-pkc-MTL-SHAKE-128"
    "OV-III-pkc-MTL-SHAKE-192"
    "OV-V-pkc-MTL-SHAKE-256"
    "OV-Is-pkc-skc-MTL-SHAKE-128"
    "OV-Ip-pkc-skc-MTL-SHAKE-128"
    "OV-III-pkc-skc-MTL-SHAKE-192"
    "OV-V-pkc-skc-MTL-SHAKE-256"
    "SNOVA_24_5_4-MTL-SHAKE-128"
    "SNOVA_24_5_4_SHAKE-MTL-SHAKE-128"
    "SNOVA_24_5_4_esk-MTL-SHAKE-128"
    "SNOVA_24_5_4_SHAKE_esk-MTL-SHAKE-128"
    "SNOVA_37_17_2-MTL-SHAKE-128"
    "SNOVA_25_8_3-MTL-SHAKE-128"
    "SNOVA_56_25_2-MTL-SHAKE-192"
    "SNOVA_49_11_3-MTL-SHAKE-192"
    "SNOVA_37_8_4-MTL-SHAKE-192"
    "SNOVA_24_5_5-MTL-SHAKE-192"
    "SNOVA_60_10_4-MTL-SHAKE-256"
    "SNOVA_29_6_5-MTL-SHAKE-256" )

FL=$(find $TD/ -type f -name "*.msg" -print0 | xargs -0 printf "%s ")

###################################################################
# Test the keygen, sign, and verify tools in binary string format
###################################################################
for i in "${schemes[@]}"
do
    rm -rf $TD/testkey.*
    # echo "./mtlkeygen $TD/testkey "$i""
    KEYGEN_TIME=$( TIMEFORMAT="%R"; { time ( ./mtlkeygen $TD/testkey "$i" > $TD/keygen.output.shell ); } 2>&1 )

    # echo "./mtlsign $TD/testkey.key $FL"
    SIGN_TIME=$( TIMEFORMAT="%R"; { time ( ./mtlsign -r $TD/testkey.key $FL > $TD/sign.output.shell ); } 2>&1 ) 


    SIGNATURES=0
    TOTAL_CONDENSED_VERIFY_TIME=0
    TOTAL_FULL_VERIFY_TIME=0
    FAILURES=0
    for msg in $FL; do
        # echo "./mtlverify $i $TD/testkey.pub $msg $msg.condensed_sig -t $TD/testkey.key.ladder"
        CONDENSED_VERIFY_TIME=$( TIMEFORMAT="%R"; { time ( ./mtlverify $i $TD/testkey.pub $msg $msg.condensed_sig -t $TD/testkey.key.ladder >/dev/null ); } 2>&1 )
        if [ $? -ne 0 ]; then
                ((FAILURES++))
                echo "!!!! ERROR - Verification Error on $msg for scheme $i"
        fi
        TOTAL_CONDENSED_VERIFY_TIME=$(echo "$TOTAL_CONDENSED_VERIFY_TIME + $CONDENSED_VERIFY_TIME" | bc)

        # echo "./mtlverify $i $TD/testkey.pub $msg $msg.full_sig"
        FULL_VERIFY_TIME=$( TIMEFORMAT="%R"; { time ( ./mtlverify -t $i $TD/testkey.pub $msg $msg.full_sig >/dev/null ); } 2>&1 )
        if [ $? -ne 0 ]; then
                ((FAILURES++))
                echo "!!!! ERROR - Verification Error on $msg for scheme $i"
        fi
        TOTAL_FULL_VERIFY_TIME=$(echo "$TOTAL_FULL_VERIFY_TIME + $FULL_VERIFY_TIME" | bc)

        SIGNATURES=$((SIGNATURES + 1))
    done

    # The ladder must be verified at least once for the batch of condensed signatures to be valid (note the lack of -t)
    # This timing overestimates by the cost of 1 additional condensed verification
    CONDENSED_VERIFY_TIME=$( TIMEFORMAT="%R"; { time ( ./mtlverify $i $TD/testkey.pub $msg $msg.condensed_sig $TD/testkey.key.ladder >/dev/null ); } 2>&1 )
    TOTAL_CONDENSED_VERIFY_TIME=$(echo "$TOTAL_CONDENSED_VERIFY_TIME + $CONDENSED_VERIFY_TIME" | bc)

    RECORDS=$(find $TD/ -mindepth 1 -type f -name "*.msg" -printf x | wc -c)

    echo "  Scheme $i"
    echo "    Records Signed                  = $RECORDS messages"
    echo "    Records Verified                = $SIGNATURES messages"
    echo "    Signatures Failed               = $FAILURES signatures"
    echo "    Key Generation Time             = $(echo $KEYGEN_TIME | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    Signing Time                    = $(echo $SIGN_TIME | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    All Full Verification Time      = $(echo $TOTAL_FULL_VERIFY_TIME | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "    All Condensed Verification Time = $(echo $TOTAL_CONDENSED_VERIFY_TIME | bc -l | awk '{printf "%0.4f\n", $0}') seconds"
    echo "  "
done

echo "Testing Completed - All tests pass"
rm -rf $TD