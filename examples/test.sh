#!/bin/bash

clear
set -e

mkdir -p tmp
echo "Test Record 0" > tmp/testfile.txt
echo "Test Record 1" >> tmp/testfile.txt
echo "Test Record 2" >> tmp/testfile.txt
echo "Test Record 3" >> tmp/testfile.txt

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

for i in "${schemes[@]}"
do
    KG=$( TIMEFORMAT="%R"; { time ( ./mtltool keygen tmp/testkey.key "$i" > tmp/output.shell ); } 2>&1 ) 
    SM=$( TIMEFORMAT="%R"; { time ( ./mtltool sign tmp/testkey.key tmp/testfile.txt tmp/sigs.txt >> tmp/output.shell ); } 2>&1 ) 
    VM=$( TIMEFORMAT="%R"; { time ( ./mtltool verify tmp/testkey.key tmp/testfile.txt tmp/sigs.txt >> tmp/output.shell ); } 2>&1 ) 

    rm -f tmp/output.shell

    FAILURES=$?

    COUNT=$(wc -l "tmp/testfile.txt")
    FILESIZE=$(stat -c%s "tmp/sigs.txt" | numfmt --to=iec)
    KEYSIZE=$(stat -c%s "tmp/testkey.key" | numfmt --to=iec)	
    RECORDS=${COUNT%% *}

    echo "  Scheme $i"
    echo "    Records Signed        = $(( $RECORDS + 1))"
    echo "    Total Signature Sizes = $FILESIZE bytes"
    echo "    Key Generation Time   = $KG seconds"
    echo "    Record Signing Time   = $SM seconds"
    echo "    All Verification Time = $VM seconds"
    echo "  "

done

rm -rf tmp
