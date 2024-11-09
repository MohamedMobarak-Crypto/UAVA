from bplib import bp
from bplib.bp import BpGroup , GTElem
from petlib.bn import Bn
import hashlib
import socket
import pickle
import time
import ecdsa
from ecdsa import VerifyingKey, SECP256k1 


# Initialize bilinear pairing group
G = BpGroup()
p_bn = G.order()


def hash_to_Zp(Combined, p):
    # Hash the combined byte string using SHA-256
    hash_digest = hashlib.sha256(Combined).digest()

    # Convert the hash to an integer 
    hash_int = int.from_bytes(hash_digest, byteorder='big')
    hash_reduced_bytes = hash_int.to_bytes((hash_int.bit_length() + 7) // 8, byteorder='big')

    # Convert the byte array to a Bn object using Bn.from_binary()
    c_bn = Bn.from_binary(hash_reduced_bytes)

    return c_bn


def BBS_Sign(gpk,gsk_i,Message):

    #start_time = time.time() # Capture Start Time of signing
    #g1=gpk['g1']
    #g2=gpk['g2']
    u=gpk['u']
    v=gpk['v']
    h=gpk['h']
    w=gpk['w']
    A_i=gsk_i['A_i']
    x_i=gsk_i['x_i']

    alpha = Bn.random(p_bn)+1 # Chosen Randomly from Zp
    beta = Bn.random(p_bn)+1 # Chosen Randomly from Zp
    delta_1 = (x_i * alpha) % p_bn
    delta_2 = (x_i * beta) % p_bn

    # Calculating the helper Values
    r_alpha = Bn.random(p_bn) + 1 # chosen randomly from Zp 
    r_beta = Bn.random(p_bn) + 1 # chosen randomly from Zp 
    r_x = Bn.random(p_bn) + 1 # chosen randomly from Zp 
    r_delta1 = Bn.random(p_bn) + 1 # chosen randomly from Zp
    r_delta2 = Bn.random(p_bn) + 1 # Chosen randomly from Zp

    # Calculating Signature components (T1,T2,T3,R1,R2,R3,R4,R5)
    #=============================================================
    #T1 , belongs to G1
    #===================
    T1 = alpha * u # Scalar Multiplication

    #T2 , belongs to G1
    #===================
    T2 = beta * v # Scalar Multiplication

    #T3 , belongs to G1
    #===================
    temp = (alpha + beta) % p_bn
    T3 = A_i + (temp * h)

    # R1 , belongs to G1
    #=====================
    R1 = r_alpha * u # Scalar Multiplication

    # R2 , belongs to G1
    #====================
    R2 = r_beta * v # Scalar Multiplication

    # R3 , belongs to G2
    #=====================
    # Calculating First Pairing Term
    #e_T3_g2 = pairing(g2,T3)  # e(T3, g2)
    e_Ai_g2 = gsk_i['e_Ai_g2']
    e_h_g2 = gpk['e_h_g2']
    e_T3_g2=e_Ai_g2 * e_h_g2 ** (temp)
    e_T3_g2_x = e_T3_g2 ** r_x   # First Pairing Term


    # Calculating Second Pairing Term
    temp_raplha_rbeta = (- r_alpha - r_beta) % p_bn
    e_h_w=gpk['e_h_w']
    e_h_w_neg_alpha_beta = e_h_w ** temp_raplha_rbeta # Second Pairing Term

    # Calculating Third Pairing Term
    temp_rdelta1_rdelta2 = (- r_delta1 - r_delta2) % p_bn
    e_h_g2_neg_delta1_delta2 = e_h_g2 ** temp_rdelta1_rdelta2 # Third Pairing Term

    R3 = e_T3_g2_x * e_h_w_neg_alpha_beta * e_h_g2_neg_delta1_delta2

    # R4 , belongs to G1
    #====================
    T1rx = r_x * T1 # Scalar Multiplicaiton
    urdelta1 = r_delta1 * u # Scalar Multiplicaiton
    urdelta1_neg = - urdelta1 # grtting the negation of the point
    R4 = T1rx + urdelta1_neg # Point Addition

    # R5 , belongs to G1
    #====================
    T2rx = r_x * T2 # Scalar Multiplicaiton
    urdelta2 = r_delta2 * v # Scalar Multiplicaiton
    urdelta2_neg = - urdelta2 # grtting the negation of the point
    R5 = T2rx + urdelta2_neg # Point Addition

    # Convert G1 and G2 points to bytes
    # ===================================
    T1_bytes = T1.export()
    T2_bytes = T2.export()
    T3_bytes = T3.export()
    R1_bytes = R1.export()
    R2_bytes = R2.export()
    R3_bytes = R3.export()
    R4_bytes = R4.export()
    R5_bytes = R5.export()

    #Convert message to bytes
    #PK_i = Message['PK_i']
    D_i = Message['D_i']
    #ts = Message['ts']
    PK_i_bytes = Message['PK_i'].to_string()
    D_i_bytes = D_i.encode('utf-8')
    #ts_bytes = ts.to_bytes((timestamp.bit_length() + 7) // 8, byteorder='big')

    Message_bytes = PK_i_bytes+D_i_bytes

    Combined_bytes = T1_bytes+T2_bytes+T3_bytes+R1_bytes+R2_bytes+R3_bytes+R4_bytes+R5_bytes+Message_bytes # Combined message to be hashed in bytes format

    # calculating hash digest c
    c_bn=hash_to_Zp(Combined_bytes,p_bn)
    #print("c_bn is",c_bn)

    # Calculating the S-Values using the hashing c
    #===============================================
    # Calculating s_alpha
    s_alpha = (r_alpha + c_bn*alpha) % p_bn

    # Calculating s_beta
    s_beta = (r_beta + c_bn*beta) % p_bn

    # Calculating s_xi
    s_xi = (r_x + (c_bn*x_i)) % p_bn

    # Calculating s_delta1
    s_delta1 = (r_delta1 + (c_bn*delta_1)) % p_bn

    # Calculating s_delta2
    s_delta2 = (r_delta2 + (c_bn*delta_2)) % p_bn


# Constructing the Signature Sigma_g

    Sigma_g = {

        'T1' : T1 , 
        'T2' : T2 , 
        'T3' : T3 , 
        'c' : c_bn , 
        's_alpha' : s_alpha , 
        's_beta' : s_beta , 
        's_xi' : s_xi ,
        's_delta1' : s_delta1,
        's_delta2' : s_delta2

    }

    Sigma_g_bytes = {
            'T1_bytes' : T1_bytes ,
            'T2_bytes' : T2_bytes ,
            'T3_bytes' : T3_bytes ,
            'c' : int(c_bn) ,
            's_alpha' : int(s_alpha) ,
            's_beta' : int(s_beta) ,
            's_xi' : int(s_xi) ,
            's_delta1' : int(s_delta1) ,
            's_delta2' : int(s_delta2) ,
            'D_i_bytes' : D_i_bytes,
            'PK_i_bytes' : PK_i_bytes
            }
    

    #end_time = time.time()
    #Execution_time_sign = end_time-start_time
    #print(f"Execution time of signing is :{Execution_time_sign} seconds")

    return Sigma_g , Sigma_g_bytes


if __name__ == "__main__":

    #server_ip = '192.168.1.70' # ip address of mac on wireless
    server_ip = '192.168.2.1' # ip address of mac on ethernet connection
    server_port = 12345 # proposed port for communication

     # Initializing the socket programming for the client
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # [1] ========*****Registeration Phase*****========== 
    # Sending Registeration request to MSP
    Reg_request = "Mohamed Mobarak"
    client_socket.sendall(Reg_request.encode('utf-8'))

    # Receiving group public key gpk in bytes format
    gpk_serialized= client_socket.recv(16384)
    deserialized_gpk = pickle.loads(gpk_serialized)

    # Reconstruction of gpk
    g1_bytes=deserialized_gpk['g1_bytes']
    g1 = bp.G1Elem.from_bytes(g1_bytes,G)
    g2_bytes=deserialized_gpk['g2_bytes']
    g2 = bp.G2Elem.from_bytes(g2_bytes,G)

    u_bytes=deserialized_gpk['u_bytes']
    u = bp.G1Elem.from_bytes(u_bytes,G)

    v_bytes=deserialized_gpk['v_bytes']
    v = bp.G1Elem.from_bytes(v_bytes,G)

    h_bytes=deserialized_gpk['h_bytes']
    h = bp.G1Elem.from_bytes(h_bytes,G)

    w_bytes=deserialized_gpk['w_bytes']
    w = bp.G2Elem.from_bytes(w_bytes,G)

    e_g1_g2_bytes = deserialized_gpk['e_g1_g2_bytes']
    e_g1_g2 = GTElem.from_bytes(e_g1_g2_bytes, G)

    e_h_g2_bytes = deserialized_gpk['e_h_g2_bytes']
    e_h_g2 = GTElem.from_bytes(e_h_g2_bytes, G)

    e_h_w_bytes = deserialized_gpk['e_h_w_bytes']
    e_h_w = GTElem.from_bytes(e_h_w_bytes, G)


    gpk = {
        'g1': g1,
        'g2': g2,
        'h': h,
        'u': u,
        'v': v,
        'w': w,
        'e_h_w' : e_h_w,
        'e_h_g2' : e_h_g2,
        'e_g1_g2' : e_g1_g2
        }

    gpk_received = "gpk received"
    client_socket.sendall(gpk_received.encode('utf-8'))

    # Receiving gsk_i
    #=====================
    gsk_i_serialized = client_socket.recv(4096)
    gsk_i_deserialized = pickle.loads(gsk_i_serialized)

    #Reconstruction of gsk_i
    A_i_bytes = gsk_i_deserialized['A_i_bytes']
    A_i = bp.G1Elem.from_bytes(A_i_bytes,G)
    x_i_int = gsk_i_deserialized['x_i_bytes']
    #print("type of x_i_bytes",type(x_i_int))
    x_i_bytes = x_i_int.to_bytes((x_i_int.bit_length() + 7) // 8, byteorder='big')
    x_i = Bn.from_binary(x_i_bytes) # Convert the byte array to a Bn object using Bn.from_binary()
    e_Ai_g2_bytes = gsk_i_deserialized['e_Ai_g2_bytes']
    e_Ai_g2 = GTElem.from_bytes(e_Ai_g2_bytes,G)


    gsk_i = {
        'A_i' : A_i,
        'x_i' : x_i,
        'e_Ai_g2' : e_Ai_g2
    }

    #====================*****End of Registeration Phase****====================
    #===========================================================================

    # [2] ========***** Avatar Creation Phase*****========== 

    # A] Generating D_i : Textual describtion of the Avatar
    D_i = "Avatar 1 nickname"

    # B] Generating a pair of secret keys for ECDSA 
    # Sympols for user secret key is SK_i , while user public key is PK_i
    SK_i = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) # Generating user secret key 
    PK_i = SK_i.get_verifying_key() # getting corresponding public key

    # C] Creating user virtual identity Idv_i
    Idv_i = {
        'D_i' : D_i,
        'PK_i' : PK_i
    }

    # D] Creating user certificates Cert_i = (Sigma_g_i,Idv_i)
    Cert_i , Cert_i_bytes = BBS_Sign(gpk,gsk_i,Idv_i)




    #===================*****End of Avatar Creation Phase****===================
    #===========================================================================    

    # [3] ===============***** Avatar Authentication Phase *****=============== 

    # A] Generating a timstamp ts and sign it using ECDSA secret key
    Start_time = time.time()
    ts=int(time.time()) # Get current Timestamp
    ts_str = f"{ts}"
    #print("type of ts is ",type(ts))
    #print("type of ts_str is ",type(ts_str))

    Sigma_s_i = SK_i.sign(ts_str.encode(),hashfunc=hashlib.sha256) # Signing the current timestamp with ECDSA secret key SK_i
    
    #print("Type of Sigma_S-i",type(Sigma_s_i))

    #try:
    #    PK_i.verify(Sigma_s_i,ts_str.encode(), hashfunc=hashlib.sha256)
    #    print("signature is valid")
    #except ecdsa.BadSignatureError:
    #    print (" signature is invalid")

    # B] creating Authentication request : Auth_request = (Cert_i , Sigma_s_i , ts)
    Auth_req = {
        'Cert_i_bytes' : Cert_i_bytes,
        'Sigma_s_i' : Sigma_s_i,
        'ts' : ts
    }

    Auth_req_serialized = pickle.dumps(Auth_req)
    client_socket.sendall(Auth_req_serialized)


    Auth_reply = client_socket.recv(1024)
    End_time = time.time()
    Auth_reply = Auth_reply.decode('utf-8')
    print("Authentication Decision is ",Auth_reply)
    
    Auth_Exec_time = End_time - Start_time
    print(f"Authentication Execution time is :{Auth_Exec_time} seconds")