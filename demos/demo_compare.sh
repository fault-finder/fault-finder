#!/bin/bash

#!/bin/bash

# Define the files
inputs=("tiny-AES-arm" "tiny-AES-riscv" "tiny-AES-x86" "tiny-AES-tricore")

# Iterate over the inputs and run a command on them
for file in "${inputs[@]}"; do
    echo "Processing $file..."
    docker run --rm -it -v $(pwd)/demos:/usr/src/faultfinder/demos faultfinder demos/$file/jsons/fault.json
done

# Iterate over the output directories named the same as the inputs
for file in "${inputs[@]}"; do
    echo "--- Results for $file ---"
    dir="demos/${file}/outputs"
    cat $dir/*  | grep Output| sort | uniq -c
done
