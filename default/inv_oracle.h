/* Inverse p-layer for a 128-bit state represented by two u64s (state[0] left 64, state[1] right 64) */
void inv_p_layer(uint64_t *msg){
    /* inverse permutation table of baksheesh same as gift */
    uint8_t inv_perm_table[128] = { 
      0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63,
      64, 69, 74, 79, 80, 85, 90, 95, 96, 101, 106, 111, 112, 117, 122, 127,
      12, 1, 6, 11, 28, 17, 22, 27, 44, 33, 38, 43, 60, 49, 54, 59,
      76, 65, 70, 75, 92, 81, 86, 91, 108, 97, 102, 107, 124, 113, 118, 123,
      8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55,
      72, 77, 66, 71, 88, 93, 82, 87, 104, 109, 98, 103, 120, 125, 114, 119,
      4, 9, 14, 3, 20, 25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51,
      68, 73, 78, 67, 84, 89, 94, 83, 100, 105, 110, 99, 116, 121, 126, 115};

    /* to store permutation values of each half */
    uint64_t cip[2] = {0};

    for(uint8_t i=0; i<128; i++){
        uint8_t half = i/64;

        /* for the bit positions, if the permutation bit is within [0, 63], keep the bit in right side of the */
        /* return msg, else keep it in the left */
        if (inv_perm_table[i] < 64){
            cip[1] |= (((msg[1 - half] >> (i%64))&1) << inv_perm_table[i]);
        }

        else{
            cip[0] |= (((msg[1 - half] >> (i%64))&1) << (inv_perm_table[i] - 64));
        }
    }

    msg[0] = cip[0];    msg[1] = cip[1];

    /* for printing purpose */
    if (print_details == "true"){
        print("after p-layer:\t", msg, 128);
    }
}

/* sbox layer of default cipher, depending upon the layer and core the corresponding sbox will be applied */
void inv_sbox(uint64_t *msg){
    /* inv sbox table for default layer */
    uint8_t inv_sbox_default_table[16] = {0x0, 0xa, 0xd, 0x1, 0x5, 0xf, 0xe, 0x2, 0xb, 0x7, 0x6, 0xc, 0x8, 0x4, 0x3, 0x9};

    /* applying sbox on the half */
    for (uint8_t half=0; half<2; half++){
        uint64_t cip = 0;

        /* applying sbox on each nibble */
        for(int8_t i=15;i>=0;i--){
            uint8_t nibble = inv_sbox_default_table[(msg[half] >> 4*i)&0xf];;
            cip = (cip << 4)|(nibble&0xf);
        }

        msg[half] = cip;
    }
}
