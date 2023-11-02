#!/bin/bash

clear
set -e

mkdir -p tmp
echo "Test Record 0" > tmp/testfile.txt
echo "Test Record 1" >> tmp/testfile.txt
echo "Test Record 2" >> tmp/testfile.txt
echo "Test Record 3" >> tmp/testfile.txt

declare -a schemes=("SPHINCS+-MTL-SHAKE-128S-SIMPLE" "SPHINCS+-MTL-SHAKE-128S-ROBUST"
					 "SPHINCS+-MTL-SHAKE-128F-SIMPLE" "SPHINCS+-MTL-SHAKE-128F-ROBUST"
                    			 "SPHINCS+-MTL-SHAKE-192S-SIMPLE" "SPHINCS+-MTL-SHAKE-192S-ROBUST"
					 "SPHINCS+-MTL-SHAKE-192F-SIMPLE" "SPHINCS+-MTL-SHAKE-192F-ROBUST"
					 "SPHINCS+-MTL-SHAKE-256S-SIMPLE" "SPHINCS+-MTL-SHAKE-256S-ROBUST"
					 "SPHINCS+-MTL-SHAKE-256F-SIMPLE" "SPHINCS+-MTL-SHAKE-256F-ROBUST"
					 "SPHINCS+-MTL-SHA2-128S-SIMPLE" "SPHINCS+-MTL-SHA2-128S-ROBUST"
					 "SPHINCS+-MTL-SHA2-128F-SIMPLE" "SPHINCS+-MTL-SHA2-128F-ROBUST"
					 "SPHINCS+-MTL-SHA2-192S-SIMPLE" "SPHINCS+-MTL-SHA2-192S-ROBUST"
					 "SPHINCS+-MTL-SHA2-192F-SIMPLE" "SPHINCS+-MTL-SHA2-192F-ROBUST"
					 "SPHINCS+-MTL-SHA2-256S-SIMPLE" "SPHINCS+-MTL-SHA2-256S-ROBUST"
					 "SPHINCS+-MTL-SHA2-256F-SIMPLE" "SPHINCS+-MTL-SHA2-256F-ROBUST")

for i in "${schemes[@]}"
do
    echo "$i"
	RT=$( TIMEFORMAT="%R"; { time ( ./mtltool keygen tmp/testkey.key "$i" > tmp/output.shell ); } 2>&1 ) 
    ./mtltool sign tmp/testkey.key tmp/testfile.txt tmp/sigs.txt >> tmp/output.shell
    ./mtltool verify tmp/testkey.key tmp/testfile.txt tmp/sigs.txt >> tmp/output.shell

	rm tmp/output.shell

	echo "    Failures              = $?"

    COUNT=$(wc -l "tmp/testfile.txt")
    FILESIZE=$(stat -c%s "tmp/sigs.txt" | numfmt --to=iec)
	RECORDS=${COUNT%% *}

    echo "    Records Signed        = $(( $RECORDS + 1))"
    echo "    Total Signature Sizes = $FILESIZE bytes"
	echo "    Rough Execution Time  = $RT seconds"
    echo ""

done
