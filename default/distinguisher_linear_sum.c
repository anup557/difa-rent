/* gist: The code is to check the linear-sum distinguisher from the zero-sum distinguisher due to */
/* division property. The previous distinguisher was, after 6 rounds 64 bits were balanced. Here by */
/* using the LAT of default, we can write output bits (x_i) of r-round in terms of output bits (y_i) */
/* of r+1 round. Here we use the relation, x_0 ^ y_1 ^ y_2 ^ y_3 = 0. In the other bit's linear */
/* combination, x_1 or x_3 is involved. So, we can not take those. */
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

#define FAULT_ROUND 7
#define NO_OF_TIMES 1000

#define MASK 0x1111111111111111ULL

#include "my_lib.h"
#include "oracle.h"

/* permutation layer, same as gift-128 */
void inv_p_layer(uint64_t *msg){
    /* permutation table of baksheesh same as gift */
    uint8_t perm_table[128] = {0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63, 64, 69,
        74, 79, 80, 85, 90, 95, 96, 101, 106, 111, 112, 117, 122, 127, 12, 1, 6, 11, 28, 17, 22, 27,
        44, 33, 38, 43, 60, 49, 54, 59, 76, 65, 70, 75, 92, 81, 86, 91, 108, 97, 102, 107, 124, 113,
        118, 123, 8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55, 72, 77, 66, 71, 88,
        93, 82, 87, 104, 109, 98, 103, 120, 125, 114, 119, 4, 9, 14, 3, 20, 25, 30, 19, 36, 41, 46,
        35, 52, 57, 62, 51, 68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99, 116, 121, 126, 115};

    /* to store permutation values of each half */
    uint64_t cip[2] = {0};

    for(uint8_t i=0; i<128; i++){
        uint8_t half = i/64;

        /* for the bit positions, if the permutation bit is within [0, 63], keep the bit in right side of the */
        /* return msg, else keep it in the left */
        if (perm_table[i] < 64){
            cip[1] |= (((msg[1 - half] >> (i%64))&1) << perm_table[i]);
        }

        else{
            cip[0] |= (((msg[1 - half] >> (i%64))&1) << (perm_table[i] - 64));
        }
    }

    msg[0] = cip[0];    msg[1] = cip[1];
}


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
    uint64_t *linear_sum = mem_alloc(STATE_SIZE);

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

        /* applying inverse permutation layer to go just below of the sbox layer */
        inv_p_layer(xor_sum);

        /* checking linear sum (y_1 ^ y_2 ^ y_3) */
        linear_sum[0] ^= (xor_sum[0]>>1)&MASK;  linear_sum[1] ^= (xor_sum[1]>>1)&MASK;
        linear_sum[0] ^= (xor_sum[0]>>2)&MASK;  linear_sum[1] ^= (xor_sum[1]>>2)&MASK;
        linear_sum[0] ^= (xor_sum[0]>>3)&MASK;  linear_sum[1] ^= (xor_sum[1]>>3)&MASK;
    }

    /* Print summary. */
    printf("fault round: %d\n", FAULT_ROUND);
    printf("fault injected at %d-round.\n", NO_OF_ROUNDS - FAULT_ROUND);

    /* printf("fault injected at %d nibble in %d-round.\n", fault_nibble_index, NO_OF_ROUNDS - FAULT_ROUND); */
    print("linear sum: ", linear_sum, STATE_SIZE);
}

