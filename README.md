# FaultFinder

Welcome to FaultFinder: lightning-fast, multi-architectural fault injection simulation

This repository accompanies the paper presented in the ASHES'24 workshop.


## Installation

You can [build and run in a Docker container](#docker) or [build and run locally](#by-hand) (at least in Linux and MacOS). Once you have an executable to run, continue to the [Demonstrations](#demonstrations).

### Docker

```
docker build -t faultfinder .
```

Then to run:

```
docker run --rm -it -v $(pwd)/demos:/usr/src/faultfinder/demos faultfinder [path to json file]
```

Note: the `-v` option assumes you are running from the root of the FaultFinder checkout. If you are running elsewhere, or when you are working with your own projects, you will need to tweak the `-v` option to 'mount' the appropriate local folder into the docker machine's filesystem.

See the [Demonstrations](#demonstrations) for example commands to run.



### By hand

* Clone this repo
* Install libjson-c-dev
* Install pkgconfig
* Build and Install libcapstone 5.x - following their instructions
* Build and Install unicorn 2.1.1 - following their instructions

Then:
```
ldconfig
make faultfinder
./faultfinder [path to json file]
```
See the [Demonstrations](#demonstrations) for example commands to run.


# Demonstrations

Examples with three different architectures producing identical results

## tinyAES compiled for ARM
### Goldenrun

1. Review the json file at `demos/tiny-AES-arm/jsons/goldenrun_full.json` - note most options are disabled to simply give the output as quickly as possible.
2. Review the binary json file at `demos/tiny-AES-arm/jsons/binary-details.json`. The content here is fairly self-explanatory. Any options left empty will result in a report from the tool giving clues as to valid values. Note that paths are relative to the execution directory of faultfinder.  This file is the core of the operation and captures all the inputs, manipulations to perform in order to correctly execute (patching instructions/data values, skipping instructions) and what outputs should be captured.
3. Check that it all works:

```
docker run --rm -it -v $(pwd)/demos:/usr/src/faultfinder/demos faultfinder demos/tiny-AES-arm/jsons/goldenrun_full.json
```

This should end up with:

```
 >> Total instructions in faulting range:   5233
 >>> Output from address (0x00080f10) in register (R0) : 3ad77bb40d7a3660a89ecaf32466ef97
 >>> Output from address (0x00080f20) in register (R1) : 3ad77bb40d7a3660a89ecaf32466ef97
Finished.
```

### Injecting faults:

1. Review the fault configuration at `demos/tiny-AES-arm/jsons/fault.json` - note we use the same `binary-details.json`.
2. Review the fault model at `demos/tiny-AES-arm/faultmodels/small-arm.txt` - note this is not a JSON file, but a format defined for this tool. We are requesting the change of `r5` for any opcode at instruction 3864 - this was found by inspection to be the appropriate place for this demo.  Instead a much wider range of registers and instructions could be faulted in order to find the correct parameters.  Any single bit is flipped (through the use of the XOR operation and masks: 1<0<32 - meaning one bite is flipped between bits 0 and 31.
3. Run the FI:

```
docker run --rm -it -v $(pwd)/demos:/usr/src/faultfinder/demos faultfinder demos/tiny-AES-arm/jsons/fault.json
```


To view the outputs:
```
cat demos/tiny-AES-arm/outputs/*  | grep Output| sort | uniq -c
```

Shows the number of times each fault ocurred and what the outputs were.

## Run 4 architectures and compare the results

Run each of the `fault.json` files from the various demo folders and compare the results. This is automated for Docker in this script:

```
demos/demo_compare.sh
```

The reasons for the one line difference between the x86/Arm on one hand and Tricore/RiscV have not been investigated fully.
