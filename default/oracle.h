/* gist: this is the cipher code for default cipher. The test vectors are checked. The test vectors corresponding to the cipher is */ 
/* given in the original paper of default, named: "DEFAULT: Cipher Level Resistance Against */
/* Differential Fault Attack" (url: https://eprint.iacr.org/2021/712.pdf) */
/* --------------------------------------------------------------------------------------------------------------- */

/* If the print details is true then only all the state values will print */
char *print_details = "false";
/* char *print_details = "true"; */


/* sbox layer of default cipher, depending upon the layer and core the corresponding sbox will be applied */
void sbox(uint64_t *msg, char* layer){
    /* sbox table for default layer */
    uint8_t sbox_default_table[16] = {0x0, 0x3, 0x7, 0xE, 0xD, 0x4, 0xA, 0x9, 0xC, 0xF, 0x1, 0x8, 0xB, 0x2, 0x6, 0x5};
    /* sbox table for default core */
    uint8_t sbox_core_table[16] = {0x1, 0x9, 0x6, 0xf, 0x7, 0xc, 0x8, 0x2, 0xa, 0xe, 0xd, 0x0, 0x4, 0x3, 0xb, 0x5};

    if(layer == "default"){
        /* applying sbox on the half */
        for (uint8_t half=0; half<2; half++){
            uint64_t cip = 0;

            /* applying sbox on each nibble */
            for(int8_t i=15;i>=0;i--){
                uint8_t nibble = sbox_default_table[(msg[half] >> 4*i)&0xf];;
                cip = (cip << 4)|(nibble&0xf);
            }

            msg[half] = cip;
        }
    }
        
    if(layer == "core"){
        /* applying sbox on the half */
        for (uint8_t half=0; half<2; half++){
            uint64_t cip = 0;

            /* applying sbox on each nibble */
            for(int8_t i=15;i>=0;i--){
                uint8_t nibble = sbox_core_table[(msg[half] >> 4*i)&0xf];;
                cip = (cip << 4)|(nibble&0xf);
            }

            msg[half] = cip;
        }
    }

    /* for printing purpose */
    if (print_details == "true"){
        print("after sbox:\t", msg, 128);
    }
}

    
/* permutation layer, same as gift-128 */
void p_layer(uint64_t *msg){
    /* permutation table of baksheesh same as gift */
    uint8_t perm_table[128] = { 0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
                                4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
                                8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
                                12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
                                16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
                                20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
                                24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
                                28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31};

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

    /* for printing purpose */
    if (print_details == "true"){
        print("after p-layer:\t", msg, 128);
    }
}


/* adding round constant, same as gift-128 */
void add_rc(uint64_t *msg, uint8_t round_number){
   /* defining round constants for default layer and core */
    uint8_t rc_default[28] = {1, 3, 7, 15, 31, 62, 61, 59, 55, 47, 30, 60, 57, 51, 39, 14, 29, 58, 53, 43, 22, 44, 24, 48, 33, 2, 5, 11};
    uint8_t rc_core[24] = {1, 3, 7, 15, 31, 62, 61, 59, 55, 47, 30, 60, 57, 51, 39, 14, 29, 58, 53, 43, 22, 44, 24, 48};

    /* round contant positions of baksheesh */
    uint8_t rcon_pos[6] = {3, 7, 11, 15, 19, 23};

    /* initializing rcon for left and right 64 bits */
    uint64_t *rcon = mem_alloc(STATE_SIZE);

    /* making the round constant for the initial default layer */
    if (round_number < 28){
        /* making the round constant depending upon the round number */
        for(int64_t i=0;i<6;i++){
            /* taking the rc bit in the corresp pos to rcon_bit */
            uint64_t rcon_bit = (rc_default[round_number]>>i)&1;

            /* the round constant pos is within [64, 127] */
            if (rcon_pos[i] < 64){
                rcon[1] |= rcon_bit << rcon_pos[i];
            }
            /* the round constant pos is within [0, 63] */
            else{
                rcon[0] |= rcon_bit << (rcon_pos[i]-64);
            }
        }
    }

    /* making the round constant for default core */
    else if (round_number < 52){
        /* making the round constant depending upon the round number */
        for(int64_t i=0;i<6;i++){
            /* taking the rc bit in the corresp pos to rcon_bit */
            uint64_t rcon_bit = (rc_core[round_number - 28]>>i)&1;

            /* the round constant pos is within [64, 127] */
            if (rcon_pos[i] < 64){
                rcon[1] |= rcon_bit << rcon_pos[i];
            }
            /* the round constant pos is within [0, 63] */
            else{
                rcon[0] |= rcon_bit << (rcon_pos[i]-64);
            }
        }
    }

    /* making the round constant for the last default layer */
    else{
        /* making the round constant depending upon the round number */
        for(int64_t i=0;i<6;i++){
            /* taking the rc bit in the corresp pos to rcon_bit */
            uint64_t rcon_bit = (rc_default[round_number - 52]>>i)&1;

            /* the round constant pos is within [64, 127] */
            if (rcon_pos[i] < 64){
                rcon[1] |= rcon_bit << rcon_pos[i];
            }
            /* the round constant pos is within [0, 63] */
            else{
                rcon[0] |= rcon_bit << (rcon_pos[i]-64);
            }
        }
    }

    /* xoring the round constant */
    xr(msg, rcon, 128);

    /* defining rc for key schedule */
    uint64_t *rc  = mem_alloc(STATE_SIZE);
    insert(rc, 0x8000000000000000, 0x0);
    xr(msg, rc, STATE_SIZE);

    /* for printing purpose */
    if (print_details == "true"){
        print("after add-rc:\t", msg, 128);
    }
}


/* key schedule function */
void generate_round_keys(uint64_t *round_key, uint64_t *key){
    copy(&round_key[0], key, KEY_SIZE);

    /* defining rc for key schedule */
    uint64_t *rc  = mem_alloc(STATE_SIZE);
    insert(rc, 0x8000000000000000, 0x0);

    for(uint8_t round=0; round < 3; round++){
        /* generating rc for key schedule */
        copy(&round_key[2*(round+1)], &round_key[2*round], KEY_SIZE);

        /* applying round function for 4 rounds, without add round key and modified rc */
        for (uint8_t i=0; i<4; i++){
            sbox(&round_key[2*(round+1)], "default");
            p_layer(&round_key[2*(round+1)]);
            xr(&round_key[2*(round+1)], rc, STATE_SIZE);
        }
    }

    /* for printing purpose */
    if (print_details == "true"){
        printf("\n************************************************************************************\n");
        printf("round keys:\n");
        printf("************************************************************************************\n");

        for(uint8_t round=0; round < 4; round++){
            print("", &round_key[2*round], KEY_SIZE);
        }
    }
}


void add_round_key(uint64_t *msg, uint64_t *round_key){
    xr(msg, round_key, STATE_SIZE);

    /* for printing purpose */
    if (print_details == "true"){
        print("after add rk: \t", msg, 128);
    }
}



/* defining oracle */
void oracle(uint64_t *msg, uint64_t *key){
    /* allocating mem for round keys, here they have used 4 independent round keys, that is added in the rounds in a rotating fashion */
    uint64_t *round_key_layer = mem_alloc(KEY_SIZE*4);

    /* for printing purpose */
    if (print_details == "true"){
        printf("************************************************************************************\n\n");
    }

    /* generating 4 independent round keys for the default cipher */
    generate_round_keys(round_key_layer, key);

    for(int8_t round=0; round < NO_OF_ROUNDS; round++){
        if (print_details == "true"){
            if (round == 0){
                printf("\n\n************************************************************************************\n\n");
                printf("default layer (initial):\n\n");
            }

            if (round == 28){
                printf("\n\n************************************************************************************\n\n");
                printf("default core:\n\n");
            }

            if (round == 52){
                printf("\n\n************************************************************************************\n\n");
                printf("default layer (last):\n\n");
            }

            printf("\n************************************************************************************\n");
            printf("for round %d: \n", round);
            printf("************************************************************************************\n");
        }


        /* for intial default layer */
        if (round < 28){
            sbox(msg, "default");
            p_layer(msg);
            add_round_key(msg, &round_key_layer[2*(round%4)]);
            add_rc(msg, round);
        }

        /* for default core */
        else if (round < 52){
            sbox(msg, "core");
            p_layer(msg);
            add_round_key(msg, &round_key_layer[2*(round%4)]);
            add_rc(msg, round);
        }

        else{
            sbox(msg, "default");
            p_layer(msg);
            add_round_key(msg, &round_key_layer[2*(round%4)]);
            add_rc(msg, round);
        }
    }

    if (print_details == "true"){
        printf("************************************************************************************\n");
    }
}


/* defining fault oracle */
void foracle(uint64_t *msg, uint64_t *key, uint8_t fround, uint64_t *fval){
    /* allocating mem for round keys, here they have used 4 independent round keys, that is added in the rounds in a rotating fashion */
    uint64_t *round_key_layer = mem_alloc(KEY_SIZE*4);
    uint64_t *round_key_core = mem_alloc(KEY_SIZE*4);

    /* for printing purpose */
    if (print_details == "true"){
        printf("************************************************************************************\n\n");
    }

    generate_round_keys(round_key_layer, key);

    for(int8_t round=0; round < NO_OF_ROUNDS; round++){
        if (print_details == "true"){
            printf("\n************************************************************************************\n");
            printf("for round %d: \n", round);
            printf("************************************************************************************\n");
        }

        /* xor the fault value with the state in the fault round */
        if (round == fround){
            xr(msg, fval, STATE_SIZE);
        }

        /* for intial default layer */
        if (round < 28){
            sbox(msg, "default");
            p_layer(msg);
            add_round_key(msg, &round_key_layer[2*(round%4)]);
            add_rc(msg, round);
        }

        /* for default core */
        else if (round < 52){
            sbox(msg, "core");
            p_layer(msg);
            add_round_key(msg, &round_key_layer[2*(round%4)]);
            add_rc(msg, round);
        }

        else{
            sbox(msg, "default");
            p_layer(msg);
            add_round_key(msg, &round_key_layer[2*(round%4)]);
            add_rc(msg, round);
        }
    }

    if (print_details == "true"){
        printf("************************************************************************************\n");
    }
}


