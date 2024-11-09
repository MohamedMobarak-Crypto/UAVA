import time
from bplib.bp import BpGroup
from petlib.bn import Bn
import pandas as pd
import hashlib

G = BpGroup()

# Function to calculate Bilinear Pairing
def calculate_pairing(g1,g2):
    pairing_result = G.pair(g1,g2)
    return pairing_result

# Function to calculate scalar multiplication
def scalar_multiplication(g, scalar):
    return g * scalar

# Function to calculate point addition
def point_addition(g1):
    return g1 + g1

# Function to calculate modular inverse
def modular_exponentiation(base,exp,modulus):
    return pow(base, exp , modulus)

def hash_to_Zp(combined):
    hash_digest=hashlib.sha256(combined).digest()

def run_operations():
    iterations = 100000
    g1 = G.gen1()  # Generator in G1
    g2 = G.gen2()  # Generator in G2
    p_bn = G.order()
    scalar = G.order().random()  # Random scalar from the group order
    gamma = Bn.random(p_bn) + 1 # Chosen Randomly from Zp
    h= g1 * (Bn.random(p_bn)+1)
    w = g2 * gamma  # Scalar multiplication

    times_pairing = [] # To record each iteration execution time
    times_scalar_mult = [] # To record each iteration execution time
    times_point_add = [] # To record each iteration execution time
    times_mod_exp = [] # To record each iteration execution time
    times_hashing = [] # To record each iteration execution time

    # Timing pairing
    total_time_pairing = 0
    for _ in range(iterations):
        start_time = time.time()
        calculate_pairing(h, w)
        end_time = time.time()
        total_time_pairing += (end_time - start_time)
        times_pairing.append(end_time - start_time)
    average_time_pairing = total_time_pairing / iterations


    # Timing scalar multiplication
    total_time_scalar_mult = 0
    for _ in range(iterations):
        start_time = time.time()
        scalar_multiplication(h, scalar)
        end_time = time.time()
        total_time_scalar_mult += (end_time - start_time)
        times_scalar_mult.append(end_time - start_time)
    average_time_scalar_mult = total_time_scalar_mult / iterations

    # Timing point addition
    total_time_point_add = 0
    for _ in range(iterations):
        start_time = time.time()
        point_addition(h)
        end_time = time.time()
        total_time_point_add += (end_time - start_time)
        times_point_add.append(end_time - start_time)
    average_time_point_add = total_time_point_add / iterations



    #Timing Modular Exponentiation
    total_time_mod_exp = 0
    base = 3
    exp = G.order().random().int() # Random exponent for modular exponentiation
    modulus = G.order().int() # Group order in int format

    for _ in range(iterations):
        start_time = time.time()
        modular_exponentiation(base,exp,modulus)
        end_time = time.time()
        total_time_mod_exp += (end_time - start_time)
        times_mod_exp.append(end_time - start_time)
    average_time_mod_exp = total_time_mod_exp / iterations

    # Timing Hashing - SHA256
    total_time_hashing = 0
    message = b"example data for hashing"
    for _ in range(iterations):
        start_time = time.time()
        hash_to_Zp(message)
        end_time = time.time()
        total_time_hashing += (end_time - start_time)
        times_hashing.append(end_time - start_time)
    average_time_hashing = total_time_hashing / iterations


    # Print results
    print(f"Average pairing time over {iterations} iterations: {average_time_pairing} seconds")
    print(f"Total Pairing execution time over {iterations} iterations: {total_time_pairing} seconds")
    print(f"Average Scalar multiplication time over {iterations} iterations: {average_time_scalar_mult} seconds")
    print(f"Total Scalar multiplication execution time over {iterations} iterations: {total_time_scalar_mult} seconds")
    print(f"Average Point Addition time over {iterations} iterations: {average_time_point_add} seconds")
    print(f"Total Point Addition execution time over {iterations} iterations: {total_time_point_add} seconds")
    print(f"Average Modular Exponentiation time over {iterations} iterations: {average_time_mod_exp} seconds")
    print(f"Total Modular Exponentiation execution time over {iterations} iterations: {total_time_mod_exp} seconds")
    print(f"Average Hashing time over {iterations} iterations: {average_time_hashing} seconds")
    print(f"Total Hashing execution time over {iterations} iterations: {total_time_hashing} seconds")

    # Exporting data to Excel
    data = {
        'Pairing Time' : times_pairing,
        'Scalar Multiplication Time' : times_scalar_mult,
        'Point Addition Time' : times_point_add,
        'Modular Exponentation Time' : times_mod_exp,
        'Hashing Time' : times_hashing
    }

    df = pd.DataFrame(data)
    df.to_excel('execution_times_100000_pi.xlsx',index=False)


if __name__ == '__main__':
    run_operations()