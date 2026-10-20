This repository provides supplementary material for our work "DIFA-Rent: Division Property Based Fault Attacks on **DEFAULT** and **BAKSHEESH**".
=========================================================

## Table of contents

1. [BIZ Verification](#biz-verification)
2. [Key Recovery Attack](#key-recovery-attack)
&nbsp;

## Dependencies

The following tools need to be installed to perform the experiments:

1. **Gurobi:**
   `gurobipy` package is required within `python3` to verify the BIZ distinguishers. For this, the
   `gurobi` tool is required in the machine. This can be installed from [https://www.gurobi.com/downloads/](https://www.gurobi.com/downloads/).

2. **C and python3:**
   We have used the basic C and python3 compilers to run the programs.

## Directory Structure  

A high-level overview of the directory layout and the role of each component is provided below.

```
./
├── README.md                           # Project documentation and usage guide
├── baksheesh
│    ├── biz                            # BIZ distinguishers verification thorough MILP
│    │   ├── lp                         # Stores lp files corresponding to the rounds 
│    │   ├── result                     # Stores result files corresponding to the rounds
│    │   └── main.py                    # MAIN program to get biz distinguisher
│    │
│    ├── distinguisher_biz.c            # To check biz distinguisher in c
│    ├── distinguisher_linear_sum.c     # To check linear-sum distinguisher in c
│    └── key_recovery.c                 # Main program to run key recovery attack
│
│
└── default
     ├── biz                            # BIZ distinguishers verification thorough MILP
     │   ├── lp                         # Stores lp files corresponding to the rounds 
     │   ├── result                     # Stores result files corresponding to the rounds
     │   └── main.py                    # Main program to get biz distinguisher
     │
     ├── distinguisher_biz.c            # To check biz distinguisher in c
     ├── distinguisher_linear_sum.c     # To check linear-sum distinguisher in c
     └── key_recovery.c                 # Main program to run key recovery attack
```

## BIZ Verification

The simulation code for default and baksheesh are given in respective directories.
To run the simulation, do the following:
```bash
cd cipher_name/biz
python3 main.py
```
To find the BIZ property for some `n` number of rounds, change `ROUND = n` in `main.py` file in
the corresponding folder.


## Key Recovery Attack

The simulation code for default and baksheesh are given in respective directories.
To run the simulation, do the following:
```bash
cd cipher_name
gcc key_recovery.c -lm -o out
./out 6
```
Here `6` indicates the number of delta sets. The attack will run just by `./out` also (without any argument). In that case, it
will run with 3 delta sets. To run the attack with `m` delta sets, compile with `./out m`.


<br />
<br />
# difa_extension_simulation
