#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <pthread.h>

#define STATE_SIZE 128
#define KEY_SIZE   128

#define NUM_THREADS 4

#define NO_OF_ROUNDS 35
#define FAULT_ROUND 7
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

// --- Macros for small functions ---
#define BUILD_FAULT_MASK(f, idx, val) do { \
    (f)[0]=(f)[1]=0ULL; \
    if ((idx)<16) (f)[0] = ((uint64_t)((val)&0xF)) << (4*(15-(idx))); \
    else          (f)[1] = ((uint64_t)((val)&0xF)) << (4*(15-((idx)-16))); \
} while(0)

#define BUILD_LAST_ROUND_KEY_FOR_QR(out, qr, cand) do { \
    for(int _i=0;_i<4;_i++){ \
        uint64_t _nib=((cand)>>(4*_i))&0xF; \
        int _bitpos=(32*_i)+(4*(qr)); \
        if(_bitpos<64) (out)[1]|=_nib<<_bitpos; \
        else           (out)[0]|=_nib<<(_bitpos-64); \
    } \
} while(0)

#define INIT_ALIVE(alive) do { for(int _qr=0;_qr<8;_qr++) for(int _i=0;_i<WORDS_PER_QR;_i++) (alive)[_qr][_i]=~0ULL; } while(0)
#define IS_ALIVE(alive,cand) (((alive)[(cand)>>6]>>((cand)&63))&1ULL)
#define SET_ALIVE(alive,cand) ((alive)[(cand)>>6]|=(1ULL<<((cand)&63)))
#define COUNT_ALIVE(alive) ({ uint32_t _cnt=0; for(int _i=0;_i<WORDS_PER_QR;_i++) _cnt+=__builtin_popcountll((alive)[_i]); _cnt; })

// --- Function Definitions ---
static inline int check_linear_distinguisher(const uint64_t *xor_state, int qr){
    uint64_t y0_0 = (xor_state[0] >> 0) & MASK;   uint64_t y0_1 = (xor_state[1] >> 0) & MASK;
    uint64_t y1_0 = (xor_state[0] >> 1) & MASK;   uint64_t y1_1 = (xor_state[1] >> 1) & MASK;
    uint64_t y2_0 = (xor_state[0] >> 2) & MASK;   uint64_t y2_1 = (xor_state[1] >> 2) & MASK;
    uint64_t y3_0 = (xor_state[0] >> 3) & MASK;   uint64_t y3_1 = (xor_state[1] >> 3) & MASK;

    uint64_t mask;
    if (qr < 4) {
        mask = (uint64_t)0xFFFFULL << (16 * qr);
        uint64_t m0 = y0_1 & mask, m1 = y1_1 & mask, m2 = y2_1 & mask;
        if ( ((m0 ^ m1 ^ m2) != 0ULL) ) return 0;
    } else {
        mask = (uint64_t)0xFFFFULL << (16 * (qr - 4));
        uint64_t m0 = y0_0 & mask, m1 = y1_0 & mask, m2 = y2_0 & mask;
        if ( ((m0 ^ m1 ^ m2) != 0ULL) ) return 0;
    }
    return 1;
}

static inline int check_linear_distinguisher_2nd_last(const uint64_t *xor_state, int nib){
    uint64_t xr_val = 0ULL;
    /* extracting the xor val depending upon the qr group */
    if (nib<16){
        xr_val = (xor_state[1] >> (4*nib))&(uint64_t)0xf;
    }

    /* for original key, val of the zero sum distinguisher should be 0 */
    if (xr_val ==0){
        return 1;
    }
    else {
        return 0;
    }
}

static uint32_t reduce_qr_group(uint64_t alive[WORDS_PER_QR],
                                const uint64_t *cip16,
                                int qr_group_no)
{
    uint64_t next_alive[WORDS_PER_QR];
    memset(next_alive, 0, sizeof(next_alive));

    for (uint32_t cand = 0; cand < (1u << 16); cand++) {
        if (!IS_ALIVE(alive, cand)) continue;

        uint64_t pos_last_key[2] = {0, 0};
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key, qr_group_no, cand);

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
            SET_ALIVE(next_alive, cand);
        }
    }

    memcpy(alive, next_alive, sizeof(next_alive));
    return COUNT_ALIVE(alive);
}

void collect_cips(uint64_t *all_cip16, int m, uint64_t *key) {
    for (int t = 0; t < m; t++) {
        uint64_t *msg = mem_alloc(STATE_SIZE);
        rand_alloc(msg, STATE_SIZE);

        int rand_nibble_index = rand() & 0x1F;
        for (int i = 0; i < 16; i++){
            uint64_t fmask[2];
            BUILD_FAULT_MASK(fmask, (uint8_t)rand_nibble_index, (uint8_t)i);

            memcpy(all_cip16 + (t*32) + 2*i, msg, STATE_SIZE/8);
            foracle(all_cip16 + (t*32) + 2*i, key, NO_OF_ROUNDS - FAULT_ROUND, fmask);
            add_rc(all_cip16 + (t*32) + 2*i, NO_OF_ROUNDS - 1);
            inv_p_layer(all_cip16 + (t*32) + 2*i);
        }
    }
}

void key_recovery_last_round(uint64_t *all_cip16, int m,
                             uint64_t alive[8][WORDS_PER_QR],
                             uint32_t alive_count[8],
                             uint16_t true_word[8])
{
    printf("=================================================\n");
    printf(" Progressive reduction over m = %d experiments\n", m);
    printf("=================================================\n");

    for (int t = 0; t < m; t++) {
        const uint64_t *cip16 = all_cip16 + (t * 32);
        printf("[Experiment %d/%d]\n", t+1, m);

        for (int qr = 0; qr < 8; qr++) {
            uint32_t before = alive_count[qr];
            uint32_t after  = reduce_qr_group(alive[qr], cip16, qr);
            alive_count[qr] = after;

            int still_contains = IS_ALIVE(alive[qr], true_word[qr]);
            double pow2 = (after == 0) ? -INFINITY : (log((double)after)/log(2.0));

            printf("  QR %d: %6u -> %6u  (2^{%.2f})  %s\n",
                   qr, before, after, pow2,
                   still_contains ? "[true-key IN set]" : "[true-key OUT!]");
        }
        printf("-------------------------------------------------\n");
    }

    printf("\n==================== FINAL QR REPORT ====================\n");
    for (int qr = 0; qr < 8; qr++) {
        uint32_t sz = alive_count[qr];
        double pow2 = (sz == 0) ? -INFINITY : (log((double)sz)/log(2.0));
        int contains = IS_ALIVE(alive[qr], true_word[qr]);

        printf("QR group %d: |possible key space| = %u  i.e. 2^{%.2f}  --> %s\n",
               qr, sz, pow2,
               contains ? "original key remains." : "original key ELIMINATED.");
    }
    printf("======================================================\n");
}


// Helper: build survivors for 4 groups and apply nibble checks
static uint64_t* filter_group(uint16_t *survivors[8], uint32_t survivors_count[8],
                              int groups[4], int nibbles[], int n_nibbles,
                              uint16_t true_word[8], uint32_t *out_count, int *true_remains,
                              uint64_t *all_cip16, int m)
{
    uint64_t *list=NULL; uint32_t count=0, alloc=0; *true_remains=0;

    for (uint32_t i0=0;i0<survivors_count[groups[0]];i0++)
    for (uint32_t i1=0;i1<survivors_count[groups[1]];i1++)
    for (uint32_t i2=0;i2<survivors_count[groups[2]];i2++)
    for (uint32_t i3=0;i3<survivors_count[groups[3]];i3++) {
        uint64_t pos_last_key[2]={0ULL,0ULL};
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,groups[0],survivors[groups[0]][i0]);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,groups[1],survivors[groups[1]][i1]);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,groups[2],survivors[groups[2]][i2]);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,groups[3],survivors[groups[3]][i3]);

        uint64_t pos_2nd_last_key[2];
        memcpy(pos_2nd_last_key,pos_last_key,STATE_SIZE/8);
        p_layer(pos_2nd_last_key);
        circ_shift(pos_2nd_last_key,1,128,"left");

        int passes=1;
        for (int t=0;t<m && passes;t++) {
            uint64_t xor_dec[2]={0ULL,0ULL};
            for (int j=0;j<16;j++) {
                uint64_t tmp[2];
                memcpy(tmp,all_cip16+t*32+2*j,STATE_SIZE/8);
                xr(tmp,pos_last_key,STATE_SIZE);
                inv_sbox(tmp);
                xr(tmp,pos_2nd_last_key,STATE_SIZE);
                add_rc(tmp,NO_OF_ROUNDS-2);
                inv_p_layer(tmp);
                inv_sbox(tmp);
                xr(xor_dec,tmp,STATE_SIZE);
            }
            for (int n=0;n<n_nibbles;n++)
                if (!check_linear_distinguisher_2nd_last(xor_dec,nibbles[n])) { passes=0; break; }
        }
        if (passes) {
            if (count>=alloc) { alloc=(alloc==0)?256:alloc*2; list=(uint64_t*)realloc(list,alloc*sizeof(uint64_t)); }
            uint64_t packed=((uint64_t)survivors[groups[0]][i0]<<48)|
                             ((uint64_t)survivors[groups[1]][i1]<<32)|
                             ((uint64_t)survivors[groups[2]][i2]<<16)|
                             ((uint64_t)survivors[groups[3]][i3]);
            list[count++]=packed;
            if (survivors[groups[0]][i0]==true_word[groups[0]] &&
                survivors[groups[1]][i1]==true_word[groups[1]] &&
                survivors[groups[2]][i2]==true_word[groups[2]] &&
                survivors[groups[3]][i3]==true_word[groups[3]]){
                 *true_remains=1;
/* printf("\nfor groups (%d, %d, %d, %d), true word in combo filter group: %x %x %x %x", groups[0], groups[1], groups[2], groups[3], true_word[groups[0]], true_word[groups[1]], true_word[groups[2]], true_word[groups[3]]); */
            }
        }
    }
    *out_count=count;
    return list;
}


typedef struct {
    uint64_t *stageB1;
    uint32_t cnt1;
    uint64_t *stageB2;
    uint32_t cnt2;
    uint16_t *true_word;
    uint64_t *all_cip16;
    int m;
    uint32_t start;
    uint32_t end;
} thread_arg_t;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t final_count = 0;
static int true_final = 0;

void* final_check_worker(void *argp) {
    thread_arg_t *arg = (thread_arg_t*)argp;
    for (uint32_t a = arg->start; a < arg->end; a++) {
        for (uint32_t b = 0; b < arg->cnt2; b++) {
            uint64_t pos_last_key[2] = {0ULL,0ULL};
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,0,(arg->stageB1[a]>>48)&0xFFFF);
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,3,(arg->stageB1[a]>>32)&0xFFFF);
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,4,(arg->stageB1[a]>>16)&0xFFFF);
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,7, arg->stageB1[a]&0xFFFF);
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,1,(arg->stageB2[b]>>48)&0xFFFF);
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,2,(arg->stageB2[b]>>32)&0xFFFF);
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,5,(arg->stageB2[b]>>16)&0xFFFF);
            BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,6, arg->stageB2[b]&0xFFFF);

            uint64_t pos_2nd_last_key[2];
            memcpy(pos_2nd_last_key,pos_last_key,STATE_SIZE/8);
            p_layer(pos_2nd_last_key);
            circ_shift(pos_2nd_last_key,1,128,"left");

            int passes = 1;
            for (int t = 0; t < arg->m && passes; t++) {
                uint64_t xor_sum[2] = {0ULL,0ULL};
                for (int j = 0; j < 16; j++) {
                    uint64_t tmp[2];
                    memcpy(tmp,arg->all_cip16+t*32+2*j,STATE_SIZE/8);
                    xr(tmp,pos_last_key,STATE_SIZE);
                    inv_sbox(tmp);
                    xr(tmp,pos_2nd_last_key,STATE_SIZE);
                    add_rc(tmp,NO_OF_ROUNDS-2);
                    inv_p_layer(tmp);
                    inv_sbox(tmp);
                    xr(xor_sum,tmp,STATE_SIZE);
                }
                if (!(xor_sum[0]==0ULL && xor_sum[1]==0ULL)) passes = 0;
            }

            if (passes) {
                pthread_mutex_lock(&lock);
                final_count++;
                if ((arg->true_word[0]==(arg->stageB1[a]>>48)&0xFFFF) &&
                    (arg->true_word[3]==(arg->stageB1[a]>>32)&0xFFFF) &&
                    (arg->true_word[4]==(arg->stageB1[a]>>16)&0xFFFF) &&
                    (arg->true_word[7]== arg->stageB1[a]&0xFFFF) &&
                    (arg->true_word[1]==(arg->stageB2[b]>>48)&0xFFFF) &&
                    (arg->true_word[2]==(arg->stageB2[b]>>32)&0xFFFF) &&
                    (arg->true_word[5]==(arg->stageB2[b]>>16)&0xFFFF) &&
                    (arg->true_word[6]== arg->stageB2[b]&0xFFFF)) {
                        true_final = 1;
                }
                pthread_mutex_unlock(&lock);
            }
        }
    }
    return NULL;
}


void key_recovery_second_last_round(uint64_t *all_cip16,int m,
                                    uint64_t alive[8][WORDS_PER_QR],uint16_t true_word[8])
{
    printf("\n================ SECOND-LAST ROUND =================\n");

    uint16_t *survivors[8]; uint32_t survivors_count[8];
    for (int qr=0;qr<8;qr++) {
        uint32_t count=COUNT_ALIVE(alive[qr]);
        survivors_count[qr]=count;
        survivors[qr]=(uint16_t*)malloc(count*sizeof(uint16_t));
        uint32_t idx=0;
        for (int w=0;w<WORDS_PER_QR;w++) {
            uint64_t word=alive[qr][w];
            while(word){ int bit=__builtin_ctzll(word);
                survivors[qr][idx++]=(w<<6)|bit; word&=word-1; }
        }
    }

    int groups1[4]={0,3,4,7}, nibbles1[]={0,12,13,16,17,28,29};
    int groups2[4]={1,2,5,6}, nibbles2[]={6,7,10,11,22,23,26,27};
    uint32_t cnt1,cnt2; int true1,true2;
    uint64_t *stageB1=filter_group(survivors,survivors_count,groups1,nibbles1,7,true_word,&cnt1,&true1,all_cip16,m);
    uint64_t *stageB2=filter_group(survivors,survivors_count,groups2,nibbles2,8,true_word,&cnt2,&true2,all_cip16,m);

    printf("Stage B survivors {0,3,4,7}: %u (2^{%0.2f}) (orig %s)\n",cnt1, log(cnt1)/log(2),true1?"REMAINS":"ELIMINATED");
    printf("Stage B survivors {1,2,5,6}: %u (2^{%0.2f}) (orig %s)\n",cnt2, log(cnt2)/log(2),true2?"REMAINS":"ELIMINATED");

    // Final check: combine both groups
    uint32_t final_count=0; int true_final=0;
    for (uint32_t a=0;a<cnt1;a++)
    for (uint32_t b=0;b<cnt2;b++) {
        uint64_t pos_last_key[2]={0ULL,0ULL};
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,0,(stageB1[a]>>48)&0xFFFF);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,3,(stageB1[a]>>32)&0xFFFF);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,4,(stageB1[a]>>16)&0xFFFF);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,7, stageB1[a]&0xFFFF);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,1,(stageB2[b]>>48)&0xFFFF);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,2,(stageB2[b]>>32)&0xFFFF);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,5,(stageB2[b]>>16)&0xFFFF);
        BUILD_LAST_ROUND_KEY_FOR_QR(pos_last_key,6, stageB2[b]&0xFFFF);

        uint64_t pos_2nd_last_key[2];
        memcpy(pos_2nd_last_key,pos_last_key,STATE_SIZE/8);
        p_layer(pos_2nd_last_key); circ_shift(pos_2nd_last_key,1,128,"left");

        int passes=1;
        for (int t=0;t<m && passes;t++) {
            uint64_t xor_sum[2]={0ULL,0ULL};
            for (int j=0;j<16;j++) {
                uint64_t tmp[2]; memcpy(tmp,all_cip16+t*32+2*j,STATE_SIZE/8);
                xr(tmp,pos_last_key,STATE_SIZE); inv_sbox(tmp);
                xr(tmp,pos_2nd_last_key,STATE_SIZE); add_rc(tmp,NO_OF_ROUNDS-2);
                inv_p_layer(tmp); inv_sbox(tmp); xr(xor_sum,tmp,STATE_SIZE);
            }
            if (!(xor_sum[0]==0ULL && xor_sum[1]==0ULL)) passes=0;
        }
        if (passes) {
            final_count++;

            if ((true_word[0]==(stageB1[a]>>48)&0xFFFF) &&
                ((true_word[3]&0xffff)==((stageB1[a]>>32)&0xFFFF)) &&
                ((true_word[4]&0xffff)==((stageB1[a]>>16)&0xFFFF)) &&
                ((true_word[7]&0xffff)== (stageB1[a]&0xFFFF)) &&
                ((true_word[1]&0xffff)==((stageB2[b]>>48)&0xFFFF)) &&
                ((true_word[2]&0xffff)==((stageB2[b]>>32)&0xFFFF)) &&
                ((true_word[5]&0xffff)==((stageB2[b]>>16)&0xFFFF)) &&
                ((true_word[6]&0xffff)== ((stageB2[b]&0xFFFF)))){
                    true_final=1;
            } 
        }
    }
    printf("\nFinal survivors after 2-round check: %u (orig %s)\n",final_count,true_final?"REMAINS":"ELIMINATED");

    for (int qr=0;qr<8;qr++) free(survivors[qr]);
    free(stageB1); free(stageB2);
}






// --- Main ---
int main(int argc, char **argv){
    time_t t1 = time(NULL);

    srand((unsigned)time(NULL));
    int m=(argc>=2)?atoi(argv[1]):M_EXPERIMENTS;

    uint64_t *key = mem_alloc(KEY_SIZE);
    rand_alloc(key,KEY_SIZE);
    print("original key:",key,KEY_SIZE);

    uint64_t *round_keys = mem_alloc(KEY_SIZE*NO_OF_ROUNDS);
    generate_round_keys(round_keys,key);

    uint64_t org_last_rnd_key[2];
    memcpy(org_last_rnd_key, round_keys+2*NO_OF_ROUNDS, STATE_SIZE/8);
    inv_p_layer(org_last_rnd_key);

    uint16_t true_word[8];
    for(int qr=0;qr<8;qr++){
        true_word[qr]=
            (((org_last_rnd_key[0]>>(32+4*qr))&0xF)<<12) |
            (((org_last_rnd_key[0]>>(    4*qr))&0xF)<<8) |
            (((org_last_rnd_key[1]>>(32+4*qr))&0xF)<<4) |
            (((org_last_rnd_key[1]>>(    4*qr))&0xF)<<0);
    }

    static uint64_t alive[8][WORDS_PER_QR];
    uint32_t alive_count[8];
    INIT_ALIVE(alive);
    for(int qr=0;qr<8;qr++) alive_count[qr]=1u<<16;

    uint64_t *all_cip16 = malloc(m*32*sizeof(uint64_t));
    collect_cips(all_cip16,m,key);
    key_recovery_last_round(all_cip16,m,alive,alive_count,true_word);

    key_recovery_second_last_round(all_cip16,m,alive,true_word);
    free(all_cip16);

    return 0;
}

