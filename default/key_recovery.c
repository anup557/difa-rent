
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

#define STATE_SIZE 128
#define KEY_SIZE   128

#define NO_OF_ROUNDS 80
#define FAULT_ROUND 8
#define MASK UINT64_C(0x1111111111111111)

/* how many random-nibble experiments */
#ifndef M_EXPERIMENTS
#define M_EXPERIMENTS 3
#endif

#include "my_lib.h"
#include "oracle.h"
#include "inv_oracle.h"

#define WORDS_PER_QR 1024   // 65536 bits / 64
#define BITS_PER_WORD 64

/* Build a 128-bit (as two u64) nibble fault mask at nibble position idx with value val (0..15). */
static inline void build_fault_mask(uint64_t f[2], uint8_t idx, uint8_t val){
    f[0] = f[1] = 0ULL;
    if (idx < 16) {
        f[0] = ((uint64_t)(val & 0xF)) << (4 * (15 - idx));
    } else {
        f[1] = ((uint64_t)(val & 0xF)) << (4 * (15 - (idx - 16)));
    }
}

/* Build a (cleared) 128-bit guess of the last round key for one QR group from a 16-bit candidate.
 * candidate16 encodes 4 nibbles: nib0 at lowest 4 bits, nib1 next, etc.
 * We only place those four nibbles in positions belonging to qr_group_no; others are zero.
 * out_key must point to two u64 words and will be overwritten (zeroed first).
 */
static inline void build_last_round_key_for_qr(uint64_t *out_key, int qr_group_no, uint32_t candidate16){
    out_key[0] = 0ULL; out_key[1] = 0ULL;
    for (int i = 0; i < 4; i++){
        uint64_t nib  = (candidate16 >> (4*i)) & 0xF;
        int bitpos    = (32 * i) + (4 * qr_group_no);   /* bitpos within 128-bit state for this nibble */
        if (bitpos < 64){
            out_key[1] |= nib << bitpos;
        } else {
            out_key[0] |= nib << (bitpos - 64);
        }
    }
}


/* Linear distinguisher on xor_state (already inverted p-layer to go below sbox).
 * Computes (y1 ^ y2 ^ y3) nibblewise and checks it is zero on the 4 nibbles of the given qr group.
 * Returns 1 if passes, 0 otherwise.
 */
static inline int check_linear_distinguisher(const uint64_t *xor_state, int qr){
    uint64_t a0 = (xor_state[0] >> 1) & MASK;   uint64_t a1 = (xor_state[1] >> 1) & MASK;
    uint64_t b0 = (xor_state[0] >> 2) & MASK;   uint64_t b1 = (xor_state[1] >> 2) & MASK;
    uint64_t c0 = (xor_state[0] >> 3) & MASK;   uint64_t c1 = (xor_state[1] >> 3) & MASK;

    uint64_t linear0 = a0 ^ b0 ^ c0;
    uint64_t linear1 = a1 ^ b1 ^ c1;

    if (qr < 4){
        /* mask the 4 nibbles for this QR group in the least significant 64-bit half of state[1] */
        linear1 &= (uint64_t)0xFFFFULL << (16 * qr);
        return (linear1 == 0ULL);
    } else {
        /* mask the 4 nibbles for this QR group in state[0] */
        linear0 &= (uint64_t)0xFFFFULL << (16 * (qr - 4));
        return (linear0 == 0ULL);
    }
}

/* ---------------- Bitset helpers ---------------- */
static inline void init_alive(uint64_t alive[8][WORDS_PER_QR]) {
    for (int qr = 0; qr < 8; qr++) {
        for (int i = 0; i < WORDS_PER_QR; i++) {
            alive[qr][i] = ~0ULL;  // all candidates alive
        }
    }
}

static inline int is_alive(const uint64_t alive[WORDS_PER_QR], uint32_t cand) {
    return (alive[cand >> 6] >> (cand & 63)) & 1ULL;
}

static inline void set_alive(uint64_t alive[WORDS_PER_QR], uint32_t cand) {
    alive[cand >> 6] |= (1ULL << (cand & 63));
}

static inline void clear_alive(uint64_t alive[WORDS_PER_QR], uint32_t cand) {
    alive[cand >> 6] &= ~(1ULL << (cand & 63));
}

static inline uint32_t count_alive(const uint64_t alive[WORDS_PER_QR]) {
    uint32_t cnt = 0;
    for (int i = 0; i < WORDS_PER_QR; i++) {
        cnt += __builtin_popcountll(alive[i]);
    }
    return cnt;
}
/* ------------------------------------------------ */

/* Generate 16 faulty ciphertexts for a random nibble fault and bring them right below the last S-box.
 * Writes 16 states into cip16 (size 32 u64s since each state is 2 u64).
 * Returns the random nibble index used (0..31).
 */
static int make_faulty_set(uint64_t *cip16 /* length 32 u64s: 16 * (STATE_SIZE/64) */,
                           uint64_t *msg,
                           uint64_t *key)
{
    int rand_nibble_index = rand() & 0x1F; /* 0..31 */
    for (int i = 0; i < 16; i++){
        uint64_t fmask[2];
        build_fault_mask(fmask, (uint8_t)rand_nibble_index, (uint8_t)i);

        memcpy(cip16 + 2*i, msg, STATE_SIZE/8);
        foracle(cip16 + 2*i, key, NO_OF_ROUNDS - FAULT_ROUND, fmask);

        /* move to the place "just before the last S-box": add rc of round NO_OF_ROUNDS-1 and inverse p-layer */
        add_rc(cip16 + 2*i, NO_OF_ROUNDS - 1);
        inv_p_layer(cip16 + 2*i);
    }
    return rand_nibble_index;
}

/* Filter one QR group's candidate set using the 16 faulty ciphertexts */
static uint32_t reduce_qr_group(uint64_t alive[WORDS_PER_QR],
                                const uint64_t *cip16,
                                int qr_group_no)
{
    uint64_t next_alive[WORDS_PER_QR];
    memset(next_alive, 0, sizeof(next_alive));

    for (uint32_t cand = 0; cand < (1u << 16); cand++) {
        if (!is_alive(alive, cand)) continue;

        /* build candidate key for this QR group */
        uint64_t pos_last_key[2];
        build_last_round_key_for_qr(pos_last_key, qr_group_no, cand);

        uint64_t xor_dec[2] = {0ULL, 0ULL};
        for (int j = 0; j < 16; j++) {
            uint64_t tmp[2];
            memcpy(tmp, cip16 + 2*j, STATE_SIZE/8);

            xr(tmp, pos_last_key, STATE_SIZE);
            inv_sbox(tmp);
            inv_p_layer(tmp);
            xr(xor_dec, tmp, STATE_SIZE);
        }

        if (check_linear_distinguisher(xor_dec, qr_group_no)) {
            set_alive(next_alive, cand);
        }
    }

    memcpy(alive, next_alive, sizeof(next_alive));
    return count_alive(alive);
}

int main(int argc, char **argv){
    srand((unsigned)time(NULL));
    int m = (argc >= 2) ? atoi(argv[1]) : M_EXPERIMENTS;

    uint64_t *key = mem_alloc(KEY_SIZE);
    rand_alloc(key, KEY_SIZE);
    print("original key:", key, KEY_SIZE);

    uint64_t *round_keys = mem_alloc(KEY_SIZE*4);
    generate_round_keys(round_keys, key);

    uint64_t org_last_rnd_key[2];
    memcpy(org_last_rnd_key, round_keys + 2*3, STATE_SIZE/8);
    inv_p_layer(org_last_rnd_key);

    uint16_t true_word[8];
    for (int qr = 0; qr < 8; qr++) {
        true_word[qr] =
            (((org_last_rnd_key[0] >> (32 + 4*qr)) & 0xF) << 12) |
            (((org_last_rnd_key[0] >> (     4*qr)) & 0xF) <<  8) |
            (((org_last_rnd_key[1] >> (32 + 4*qr)) & 0xF) <<  4) |
            (((org_last_rnd_key[1] >> (     4*qr)) & 0xF) <<  0);
    }

    /* bitset per QR group */
    static uint64_t alive[8][WORDS_PER_QR];
    uint32_t alive_count[8];
    init_alive(alive);
    for (int qr = 0; qr < 8; qr++) alive_count[qr] = 1u << 16;

    printf("=================================================\n");
    printf(" Progressive reduction over m = %d experiments\n", m);
    printf("=================================================\n");

    for (int t = 0; t < m; t++) {
        uint64_t *msg = mem_alloc(STATE_SIZE);
        rand_alloc(msg, STATE_SIZE);

        uint64_t cip16[32];
        int nib = make_faulty_set(cip16, msg, key);
        printf("[Experiment %d/%d] Random fault nibble index = %d\n", t+1, m, nib);

        for (int qr = 0; qr < 8; qr++) {
            uint32_t before = alive_count[qr];
            uint32_t after  = reduce_qr_group(alive[qr], cip16, qr);
            alive_count[qr] = after;

            int still_contains = is_alive(alive[qr], true_word[qr]);
            double pow2 = (after == 0) ? -INFINITY : (log((double)after)/log(2.0));

            printf("  QR %d: %6u -> %6u  (2^{%.2f})  %s\n",
                   qr, before, after, pow2,
                   still_contains ? "[true-key IN set]" : "[true-key OUT!]");
        }
        printf("-------------------------------------------------\n");
    }

    printf("\n==================== FINAL REPORT ====================\n");
    for (int qr = 0; qr < 8; qr++) {
        uint32_t sz = alive_count[qr];
        double pow2 = (sz == 0) ? -INFINITY : (log((double)sz)/log(2.0));
        int contains = is_alive(alive[qr], true_word[qr]);

        printf("QR group %d: |possible key space| = %u  i.e. 2^{%.2f}  --> %s\n",
               qr, sz, pow2,
               contains ? "original key remains." : "original key ELIMINATED.");
    }
    printf("======================================================\n");
    return 0;
}

