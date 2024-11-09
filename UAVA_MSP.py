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

# Defining Hashing function that uses SHA256
def hash_to_Zp(Combined, p):
    # Hash the combined byte string using SHA-256
    hash_digest = hashlib.sha256(Combined).digest()

    # Convert the hash to an integer 
    hash_int = int.from_bytes(hash_digest, byteorder='big')
    hash_reduced_bytes = hash_int.to_bytes((hash_int.bit_length() + 7) // 8, byteorder='big')
# Convert the byte array to a Bn object using Bn.from_binary()
    c_bn = Bn.from_binary(hash_reduced_bytes)
    #print("h_re is",hash_reduced_bytes)
    #print("hash is",hash_int)
    #print("c_bn is",c_bn)
    #c_int = int(c_bn)
    #print("cint is",c_int)

    return c_bn

def BBS_Setup():
    # Define bilinear groups G1, G2, GT
    g1 = G.gen1()  # g1 in BBS equations
    g2 = G.gen2()  # g2 in BBS equations
    #p_bn = G.order()
    #p=21888242871839275222246405745257275088548364400416034343698204186575808495617

    # Choose random scalars gamma (γ), eta1, eta2 ∈ Zp*
    #gamma = random.randint(1, p-1)
    #eta1 = random.randint(1, p-1)
    #eta2 = random.randint(1, p-1)
    gamma = Bn.random(p_bn) + 1 # Chosen Randomly from Zp
    eta1 = Bn.random(p_bn) + 1 # Chosen Randomly from Zp
    eta2 = Bn.random(p_bn) + 1 # Chosen Randomly from Zp

    # Choose random elements h, h1 ∈ G1
    h= g1 * (Bn.random(p_bn)+1)

    # Calculate w = g2 ^ gamma, w ∈ G2 elliptic curve point
    w = g2 * gamma  # Scalar multiplication

    # Compute u and v such that u^eta1 = v^eta2 = h
    eta1_inv = pow(eta1, p_bn-2, p_bn) # Calculating Modular Inverse 
    u = h * eta1_inv # Scalar Multiplication
    #print("u is ",u)
    #print("type of u is",type(u))

    eta2_inv = pow(eta2, p_bn-2, p_bn) # Calculating Modular Inverse
    v = h * eta2_inv # Scalar Multiplication

    # Check u^eta1 = V^eta2 = h
    #h_from_u = eta1 * u
    #h_from_v = eta2 * v

    #if h_from_u == h_from_v :
     #   print("h_from_u is equal to h_from_v")
    #else: print("h_from_u is NOT equal to h_from_v")

    # Precompute pairings
    e_h_w = G.pair(h, w)
    e_h_g2 = G.pair(h, g2)
    e_g1_g2 = G.pair(g1, g2)

    # Converting gpk to bytes to be able to send it using serialization
    g1_bytes = g1.export()
    g2_bytes = g2.export()
    u_bytes = u.export()
    h_bytes = h.export()
    v_bytes = v.export()
    w_bytes = w.export()
    e_h_w_bytes = e_h_w.export()
    e_h_g2_bytes = e_h_g2.export()
    e_g1_g2_bytes = e_g1_g2.export()

    

    # Group public key gpk = (g1, g2, h, u, v, w)
    gpk = {
        'g1': g1,
        'g2': g2,
        'h': h,
        'u': u,
        'v': v,
        'w': w,
        'e_h_w': e_h_w,
        'e_h_g2': e_h_g2,
        'e_g1_g2': e_g1_g2
    }

    # Group Manager Secret key gmsk = (eta1, eta2, gamma)
    gmsk = {
        'eta1': eta1,
        'eta2': eta2,
        'gamma': gamma
    }

    gpk_bytes = {
        'g1_bytes' : g1_bytes,
        'g2_bytes' : g2_bytes,
        'u_bytes' : u_bytes,
        'v_bytes' : v_bytes,
        'h_bytes' : h_bytes,
        'w_bytes' : w_bytes,
        'e_h_w_bytes' : e_h_w_bytes,
        'e_h_g2_bytes' : e_h_g2_bytes,
        'e_g1_g2_bytes' : e_g1_g2_bytes
    }

    return gpk, gmsk , gpk_bytes

def BBS_Join(gpk,gmsk):
    #p_bn = G.order()
    g1 = gpk['g1']
    g2 = gpk['g2']
    x_i = Bn.random(p_bn) + 1 # chosen randomly from Zp
    gamma = gmsk['gamma']
    temp = (gamma + x_i) % p_bn
    temp_inverse = pow(temp, p_bn-2, p_bn)
    A_i = temp_inverse * g1
    e_Ai_g2 = G.pair(A_i,g2) # precomputed to be used in sign function

    A_i_bytes = A_i.export()
    x_i_bytes = int(x_i)
    e_Ai_g2_bytes = e_Ai_g2.export()

    gsk_i = {
        'A_i' : A_i , 
        'x_i' : x_i,
        'e_Ai_g2' : e_Ai_g2
    }
    gsk_i_bytes = {
        'A_i_bytes' : A_i_bytes,
        'x_i_bytes' : x_i_bytes,
        'e_Ai_g2_bytes' : e_Ai_g2_bytes
    }
    return gsk_i , gsk_i_bytes

def BBS_Verify(gpk,Sigma_g,Message):
    #start_time = time.time() # Capture Start Time of verifying
    #g1=gpk['g1']
    g2=gpk['g2']
    u=gpk['u']
    v=gpk['v']
    #h=gpk['h']
    w=gpk['w']
    e_g1_g2 = gpk['e_g1_g2']
    e_h_g2 = gpk['e_h_g2']
    e_h_w = gpk['e_h_w']


    T1=Sigma_g['T1']
    T2=Sigma_g['T2']
    T3=Sigma_g['T3']
    c=Sigma_g['c']
    s_alpha = Sigma_g['s_alpha']
    s_beta = Sigma_g['s_beta']
    s_xi = Sigma_g['s_xi']
    s_delta1 = Sigma_g['s_delta1']
    s_delta2 = Sigma_g['s_delta2']


    # R1_dash
    u_salpha = s_alpha * u # Scalar Multiplication
    T1_c = c * T1 # Scalar Multiplication
    T1_c_neg = - T1_c
    R1_dash = u_salpha + T1_c_neg

    # R2_dash
    v_sbeta = s_beta * v # Scalar Multiplication
    T2_c = c * T2 # Scalar Multiplication
    T2_c_neg = - T2_c
    R2_dash = v_sbeta + T2_c_neg

    # R3_dash
    temp_saplha_sbeta = (- s_alpha - s_beta) % p_bn
    temp_sdelta1_sdelta2 = (- s_delta1 - s_delta2) % p_bn

    # Calculating pairing e(T3,w^c.g2^sx)
    temp= s_xi * g2 # Scalar Multiplication
    temp1= c * w # Scalar Multiplication
    e_T3_w_g2 = G.pair(T3,(temp+temp1))
    #e_T3_w_g2 = pairing(add(temp,temp1),T3)

    #R3_dash = (e_h_w ** temp_saplha_sbeta) * (e_h_g2 ** temp_sdelta1_sdelta2) * (e_T3_w_g2) * ((e_g1_g2 ** c).inv())
    temp = e_g1_g2 **c
    R3_dash = (e_h_w ** temp_saplha_sbeta) * (e_h_g2 ** temp_sdelta1_sdelta2) * ((e_T3_w_g2) * temp.inv())

    # R4_dash 
    T1_sx = s_xi * T1
    u_sdelta1 = s_delta1 * u
    u_sdelta1_neg = - u_sdelta1
    R4_dash = T1_sx + u_sdelta1_neg

    # R5_dash 
    T2_sx = s_xi * T2
    u_sdelta2 = s_delta2 * v
    u_sdelta2_neg = - u_sdelta2
    R5_dash = T2_sx + u_sdelta2_neg

    # Converting G1 and G2 points to bytes
    # =====================================
    T1_bytes = T1.export()
    T2_bytes = T2.export()
    T3_bytes = T3.export()
    R1_dash_bytes = R1_dash.export()
    R2_dash_bytes = R2_dash.export()
    R3_dash_bytes = R3_dash.export()
    R4_dash_bytes = R4_dash.export()
    R5_dash_bytes = R5_dash.export()


    #Convert message to bytes
    PK_i = Message['PK_i']
    D_i = Message['D_i']
    #ts = Message['ts']
    PK_i_bytes = PK_i.to_string()
    D_i_bytes = D_i.encode('utf-8')
    #ts_bytes = ts.to_bytes((timestamp.bit_length() + 7) // 8, byteorder='big')

    Message_bytes = PK_i_bytes+D_i_bytes


    Combined_dash_bytes = T1_bytes+T2_bytes+T3_bytes+R1_dash_bytes+R2_dash_bytes+R3_dash_bytes+R4_dash_bytes+R5_dash_bytes+Message_bytes


    # calculating hash digest c
    c_dash=hash_to_Zp(Combined_dash_bytes,p_bn)
    #print("c is ",c)
    #print("cdash is",c_dash)

    if c == c_dash :
        check = 'True'
    else: check = 'False'


    #end_time = time.time()
    #Execution_time_Verify = end_time-start_time
    #print(f"Execution time of verifying is :{Execution_time_Verify} seconds")

    return check


if __name__ == "__main__":

    host = '0.0.0.0'  # Listen on all available interfaces
    port = 12345       # Port to listen on
    Freshness_threshold = 5 # used in testing freshness of timestamp generated by users


    # [0] =========== ******** Setup Phase *******============
    gpk , gmsk , gpk_bytes = BBS_Setup()

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"Server listening on {host}:{port}")

    # Accept a connection
    conn, addr = server_socket.accept()

    # [1] =========== ******** Registeration/Join Phase *******============
    while True:
        # Receive data from the client
        ID_i = conn.recv(1024)
        if not ID_i:
            break

        print("Data recieved from Pi is",ID_i) # received real ID of a user i

        serialized_gpk = pickle.dumps(gpk_bytes) # Sending gpk in bytes format
        #print(f"Size of serialized gpk: {len(serialized_gpk)} bytes")
        
        conn.sendall(serialized_gpk)
        gpk_reply = conn.recv(1024)

        #print("Initiating Join Phase for a user i")
        gsk_i , gsk_i_bytes =BBS_Join(gpk,gmsk)
        serialized_gski = pickle.dumps(gsk_i_bytes)
        conn.sendall(serialized_gski)

        
        #print(f"Size of serialized gski: {len(serialized_gski)} bytes")


        # [2] =========== ******** Authentication Phase *******============
        Auth_req_serialized = conn.recv(4096)
        Auth_req_deserialized = pickle.loads(Auth_req_serialized)

        #[A] : Check freshness of time stamp


        # [B] : check if the user is a valid member in the group 

        T1_bytes = Auth_req_deserialized['Cert_i_bytes']['T1_bytes']
        T1 = bp.G1Elem.from_bytes(T1_bytes,G)
        #check = is_on_curve(T1,b)

        T2_bytes = Auth_req_deserialized['Cert_i_bytes']['T2_bytes']
        T2 = bp.G1Elem.from_bytes(T2_bytes,G)

        T3_bytes = Auth_req_deserialized['Cert_i_bytes']['T3_bytes']
        T3 = bp.G1Elem.from_bytes(T3_bytes,G)

        c_int=Auth_req_deserialized['Cert_i_bytes']['c']
        #print("type of c",type(c))
        c_bytes = c_int.to_bytes((c_int.bit_length() + 7) // 8, byteorder='big')
        c_bn = Bn.from_binary(c_bytes)

        s_alpha_int = Auth_req_deserialized['Cert_i_bytes']['s_alpha']
        s_alpha_bytes = s_alpha_int.to_bytes((s_alpha_int.bit_length() + 7) // 8, byteorder='big')
        s_alpha = Bn.from_binary(s_alpha_bytes)
        
        s_beta_int = Auth_req_deserialized['Cert_i_bytes']['s_beta']
        s_beta_bytes = s_beta_int.to_bytes((s_beta_int.bit_length() + 7) // 8, byteorder='big')
        s_beta = Bn.from_binary(s_beta_bytes)


        s_xi_int = Auth_req_deserialized['Cert_i_bytes']['s_xi']
        s_xi_bytes = s_xi_int.to_bytes((s_xi_int.bit_length() + 7) // 8, byteorder='big')
        s_xi = Bn.from_binary(s_xi_bytes)

        s_delta1_int = Auth_req_deserialized['Cert_i_bytes']['s_delta1']
        s_delta1_bytes = s_delta1_int.to_bytes((s_delta1_int.bit_length() + 7) // 8, byteorder='big')
        s_delta1 = Bn.from_binary(s_delta1_bytes)

        s_delta2_int = Auth_req_deserialized['Cert_i_bytes']['s_delta2']
        s_delta2_bytes = s_delta2_int.to_bytes((s_delta2_int.bit_length() + 7) // 8, byteorder='big')
        s_delta2 = Bn.from_binary(s_delta2_bytes)

        D_i_bytes = Auth_req_deserialized['Cert_i_bytes']['D_i_bytes']
        PK_i_bytes = Auth_req_deserialized['Cert_i_bytes']['PK_i_bytes']

        D_i = D_i_bytes.decode('utf-8')
        PK_i = VerifyingKey.from_string(PK_i_bytes, curve= SECP256k1) # Converting the key to class suitable to work with the library 

        Idv_i = {
            'D_i' : D_i,
            'PK_i' : PK_i
        }

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

        #print("Verifying Algorithm Started")
        check = BBS_Verify(gpk,Sigma_g,Idv_i)
        #print(" Signature Validation is",check)

        # [B] : verify avatar identity (ECDSA verification)

        Sigma_s_i = Auth_req_deserialized['Sigma_s_i']
        ts = Auth_req_deserialized['ts']
        ts_str = f"{ts}"

        try: 
         PK_i.verify(Sigma_s_i , ts_str.encode() , hashfunc=hashlib.sha256)
         #print(" ECDSA Signature Validation : Passed ")
        except ecdsa.BadSignatureError:
            print(" ECDSA Signature Validation : Failed ")

        Auth_reply = "Access Granted"
        conn.sendall(Auth_reply.encode('utf-8'))