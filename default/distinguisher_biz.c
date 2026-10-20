/* gist: The code is to check the zero-sum distinguisher due to division property. The distinguisher */
/* is, after 6 rounds there are specific 64 bits that becomes balanced. The unknown bits are: */
/* aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa (right side is LSB) */
/* ---------------------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define STATE_SIZE 128
#define KEY_SIZE 128

/* defining rounds for default */
#define NO_OF_ROUNDS 80
#define DEFAULT_CORE 24
#define DEFAULT_LAYER 28

#define FAULT_ROUND 6
#define NO_OF_TIMES 1000

#include "my_lib.h"
#include "oracle.h"

/* Build a 128-bit (as two u64) nibble fault mask at nibble position idx with value val (0..15). */
void build_fault_mask(uint64_t f[2], uint8_t idx, uint8_t val){
    f[0] = f[1] = 0ULL;

    if (idx < 16) {
        // Left 64-bit half
        f[0] = ((uint64_t)(val & 0xF)) << (4 * (15 - idx));
    } else {
        // Right 64-bit half
        f[1] = ((uint64_t)(val & 0xF)) << (4 * (15 - (idx - 16)));
    }
}

/* Compute nibble-wise XOR-sum over an array of states (count entries).
 * out_xor[32] receives XOR of the 4-bit nibble values at each position 0..31.
 */
void xor_sum_over_outputs(uint64_t *out_xor, uint64_t *states){
    // clear the XOR accumulator
    for (int i = 0; i < 16; i++){
        xr(out_xor, states + 2*i, STATE_SIZE);
    }
}


int main(void){
    srand(time(NULL));

    uint64_t *or_sum = mem_alloc(STATE_SIZE);

    for (int i=0; i<NO_OF_TIMES; i++){
        uint64_t *msg_in = mem_alloc(STATE_SIZE);
        uint64_t *key = mem_alloc(STATE_SIZE);

        rand_alloc(msg_in, STATE_SIZE);
        rand_alloc(key, KEY_SIZE);

        /* Choose a nibble position to fault. You can fix it or randomize it. */
        uint8_t fault_nibble_index = rand()&0x1f;

        /* Collect 16 outputs where we inject nibble values 0..15 at the chosen position. */
        uint64_t *outputs = mem_alloc(16*STATE_SIZE);

        for (uint8_t val = 0; val < 16; ++val){
            uint64_t *state = mem_alloc(STATE_SIZE);
            memcpy(state, msg_in, STATE_SIZE/8);

            uint64_t *fmask = mem_alloc(STATE_SIZE);
            build_fault_mask(fmask, fault_nibble_index, val);

            foracle(state, key, NO_OF_ROUNDS - FAULT_ROUND, fmask);
            memcpy(outputs + 2*val, state, STATE_SIZE/8);
        }

        /* Compute XOR-sum per nibble across the 16 outputs. */
        uint64_t *xor_sum = mem_alloc(STATE_SIZE);
        xor_sum_over_outputs(xor_sum, outputs);

        OR(or_sum, xor_sum, STATE_SIZE);

        /* printf("fault injected at %d nibble in %d-round.\n", fault_nibble_index, NO_OF_ROUNDS - FAULT_ROUND); */
    }

    /* Print summary. */
    printf("fault round: %d\n", FAULT_ROUND);
    printf("fault injected at %d-round.\n", NO_OF_ROUNDS - FAULT_ROUND);

    print("\nor sum: ", or_sum, STATE_SIZE);
}

