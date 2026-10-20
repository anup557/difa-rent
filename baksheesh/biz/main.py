# This code is taken from "Applying MILP Method to Searching Integral Distinguishers based on
# Division Property for 6 Lightweight Block Ciphers". 
# It takes rounds, set of active bits and version as inputs and generates lp file, result file as output
# ---------------------------------------------------------------------------------------------

from cipher import Cipher
from datetime import datetime

if __name__ == "__main__":
    # taking ROUND, cipher_name as input
    ROUND = 7
    cipher_name = 'baksheesh'

    # get current time as string
    timestamp = datetime.now().strftime("%d-%b-%Y_%I-%M-%S%p")

    # naming file depending upon time stamp
    filename = f"./result/{cipher_name}_round:{ROUND}_balanced_bits_{timestamp}.txt"
    fileobj = open(filename, "w")

    total_sboxes = 32

    # store balanced bits lists for each S-box activation
    all_balanced_bits = []

    # for loop to active input 4-bits of each sbox at a time
    for i in range(total_sboxes):
        active_bit_set = [4*i, 4*i+1, 4*i+2, 4*i+3]
        fileobj.write("\n\nfor active bit " + str(active_bit_set) + ":")

        cipher = Cipher(ROUND, active_bit_set, cipher_name)
        cipher.MakeModel()

        # SolveModel now returns the balanced bits list as well
        balanced_bits = cipher.SolveModel(fileobj)
        all_balanced_bits.append(set(balanced_bits))   # store as set for easy intersection

    # after all loops: compute intersection
    if all_balanced_bits:
        intersection = set.intersection(*all_balanced_bits)
        cardinality = len(intersection)

        fileobj.write("\n\n=============================\n")
        fileobj.write("Intersection of all balanced bits:\n")
        fileobj.write(", ".join(intersection))
        fileobj.write("\nCardinality of intersection: %d\n" % cardinality)
        fileobj.write("=============================\n")

    fileobj.close()

