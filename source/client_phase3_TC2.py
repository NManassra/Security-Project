import os
import socket
import sys
import json
import base64
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getRandomNBitInteger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# modular exponentiation for efficient (base^exponent) mod modulus calculation
def modexp(base, exponent, modulus):
    # initialize result to 1 (multiplicative identity)
    result = 1
    # reduce base modulo modulus to simplify calculations
    base = base % modulus
    # loop until exponent is 0
    while exponent > 0:
        # if the least significant bit of exponent is 1, multiply result by base mod modulus
        if exponent & 1:
            result = (result * base) % modulus
        # right-shift exponent to divide by 2
        exponent >>= 1
        # square the base modulo modulus for next bit
        base = (base * base) % modulus
    # return the final modular exponentiation result
    return result

# convert integer to bytes, big endian order
def to_bytes(x):
    # calculate minimum bytes needed to represent x and convert
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# rsa keys and dh parameters (unchanged)

# alice's rsa modulus n and public exponent e
n_alice = 4947663316723336381705441725100094160113818482878502536871596891255260315279973649033668692037752057410426470446128815188834847203907223565592625612283981344001002370062389720758780778439147499167157536217555875924935944594313654333312702372722031091091110749479809499467868527888186257246276904645964663034683054341423401443059812119831778200838220496589556609214978274997933366993386651755711775370144430164088533148552806921866941525310585330243699303718962088022107680476740496398865458885117254177273835642895662554031614051272420332439990809050828709197769217427586487606145975205994864363924383582752642772301141361161019530079549737918797938456307516327174696234715893084953104611473671493329862389882048251108270766639826659485028545048203417263436921805981825640194700214358583418603076972136991795360885524826795327136108406608747390017890358671629171969953240453581234851735192516463016803798074298415079685580026361296861637642908143248924519424860206130706471487741988082769353269694050964551305332575832916614185286988190465
e_alice = 65537
# alice's private exponent d
d_alice = int(os.environ["DEMO_RSA_PRIVATE_EXPONENT"])
n_bob = 362836421996182396690073851952474850907164210287413166356945463699154609426263469035563703148671656349832054800939181288975583294772284909460784043654558339965016659891438270899043538874014948757498249806566999207662840470529119851819374425660821825374655606440370027346930419286892514853646500584312157305588482929157300979113288636211473976635605839997450001064834152105080170461945184484630944882044396490861563138170648269182129603633938459362521569541224415967273506536285543852391085927251260736816293884260117790074697072316704115195585019153118702370008961562208425949871653397089256798844042894349798004780201
e_bob = 65537
# *** this is the "wrong" private key for test case 2 (simulate trudy posing as bob) ***
d_bob = int(os.environ["DEMO_RSA_PRIVATE_EXPONENT"])
p = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5AACAA68FFFFFFFFFFFFFFFF
""".replace("\n",""), 16)
# diffie-hellman generator g
g = 2

# client id (ip)
ID_A = "192.168.1.10"

# create tcp socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to server ip and port
sock.connect(('192.168.1.16', 5000))
print("[client] connected to server.")

# function to perform dh key exchange handshake and mutual authentication
def perform_handshake(sock, ID_A):
    # generate alice's private dh exponent a (random 2048-bit integer)
    a = getRandomNBitInteger(2048)
    print(f"[client] alice's dh exponent a: {a}")  # print exponent a for debug
    
    # generate alice's random challenge RA (32 bytes)
    RA = get_random_bytes(32)
    # compute alice's dh public value A = g^a mod p
    A = modexp(g, a, p)
    # generate session initialization vector (16 bytes) for aes-cbc
    session_iv = get_random_bytes(16)
    print(f"[client] generated new session iv: {session_iv.hex()}")

    # prepare handshake message with A, RA, ID_A, IV all base64/json encoded as needed
    data = {
        'A': str(A),
        'RA': base64.b64encode(RA).decode(),
        'ID': ID_A,
        'IV': base64.b64encode(session_iv).decode()
    }
    # send handshake message to server
    sock.send(json.dumps(data).encode())

    # receive handshake response from server
    sb_raw = sock.recv(8192)
    sb = json.loads(sb_raw.decode())
    # extract server's dh public value B (int)
    B = int(sb['B'])
    # extract server's random challenge RB (bytes)
    RB = base64.b64decode(sb['RB'])
    # extract server id string
    ID_B = sb['ID']
    # extract hash H bytes
    H_bytes = bytes.fromhex(sb['H'])
    # extract server's signature on hash (int)
    Sig_B = int(sb['Sig'])

    # concatenate all values to recreate hash for verification
    concat = to_bytes(A) + to_bytes(B) + RA + RB + ID_A.encode() + ID_B.encode() + session_iv
    # hash concatenated bytes with sha256
    H_check = hashlib.sha256(concat).digest()
    H_int = int.from_bytes(H_check, 'big')

    # verify server's signature by decrypting signature with server's public key and comparing to hash
    if modexp(Sig_B, e_bob, n_bob) != H_int or H_bytes != H_check:
        print("[client] Bob authentication failed. terminating game round.")
        sock.close()
        sys.exit(1)
    print("[client] Bob authentication succeeded.")

    # sign hash using alice's private key to prove identity
    Sig_A = modexp(H_int, d_alice, n_alice)
    sa = {'Sig': str(Sig_A)}
    # send alice's signature to server
    sock.send(json.dumps(sa).encode())

    # compute shared secret = B^a mod p
    shared = modexp(B, a, p)
    # derive session key K by hashing shared secret
    K = hashlib.sha256(to_bytes(shared)).digest()

    # clear sensitive variables
    a = None
    shared = None

    # return session key and session iv
    return K, session_iv

# encrypt plaintext message with aes-cbc using key and iv
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # pad message to block size and encrypt
    return cipher.encrypt(pad(message.encode(), AES.block_size))

# decrypt ciphertext message with aes-cbc using key and iv
def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # decrypt and remove padding to get plaintext string
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# send encrypted message over socket connection and print debug info
def send_encrypted(conn, message, key, iv, label="CLIENT"):
    ciphertext = encrypt_message(message, key, iv)
    print(f"[{label}] ciphertext: {ciphertext.hex()}")
    conn.sendall(ciphertext)
    print(f"[{label}] sending plaintext: {message}")

# receive encrypted message from socket connection and decrypt it
def receive_encrypted(conn, key, iv):
    data = conn.recv(8192)
    decrypted = decrypt_message(data, key, iv)
    print(f"[client] decrypted plaintext: {decrypted}")
    return decrypted

print("[client] starting session")

try:
    # main client loop
    while True:
        print("[client] starting handshake...")
        # perform handshake and get session key and iv
        K, session_iv = perform_handshake(sock, ID_A)

        # start game session by inputting player name
        name = input("enter your name: ")
        # send player name encrypted to server
        send_encrypted(sock, name, K, session_iv)
        # receive and print welcome message from server
        print(receive_encrypted(sock, K, session_iv))

        while True:
            # receive menu from server and print
            menu = receive_encrypted(sock, K, session_iv)
            print(menu)
            # input user choice
            choice = input(">> ")
            # send choice encrypted to server
            send_encrypted(sock, choice, K, session_iv)

            if choice == '1':
                # start new round handshake for fresh keys
                print("[client] starting new round handshake...")
                K, session_iv = perform_handshake(sock, ID_A)
                # receive and print initial game message
                print(receive_encrypted(sock, K, session_iv))
                # input timed mode (y/n)
                timed = input(">> ")
                send_encrypted(sock, timed, K, session_iv)
                # receive and print confirmation
                print(receive_encrypted(sock, K, session_iv))
                # input difficulty level
                level = input(">> ")
                send_encrypted(sock, level, K, session_iv)
                # receive and print confirmation
                print(receive_encrypted(sock, K, session_iv))

                # guessing loop
                while True:
                    prompt = receive_encrypted(sock, K, session_iv)
                    print(prompt)
                    guess = input(">> ")
                    send_encrypted(sock, guess, K, session_iv)
                    result = receive_encrypted(sock, K, session_iv)
                    print(result)
                    # break if correct, timeout, or too many invalid inputs
                    if any(x in result for x in ["Correct!", "Time's up!", "Too many invalid"]):
                        break

            elif choice == '2':
                # receive leaderboard and print
                board = receive_encrypted(sock, K, session_iv)
                print(board)
                # input action (delete or back)
                action = input(">> ")
                send_encrypted(sock, action, K, session_iv)
                # if delete, receive prompt, input name, send name, print result
                if action.upper() == 'D':
                    print(receive_encrypted(sock, K, session_iv))
                    name_to_delete = input(">> ")
                    send_encrypted(sock, name_to_delete, K, session_iv)
                    print(receive_encrypted(sock, K, session_iv))

            elif choice == '3':
                # receive and print game history and press enter prompt
                print(receive_encrypted(sock, K, session_iv))
                print(receive_encrypted(sock, K, session_iv))
                # send any key to return
                send_encrypted(sock, "\n", K, session_iv)

            elif choice == '4':
                # receive and print goodbye message, then close socket and exit
                print(receive_encrypted(sock, K, session_iv))
                sock.close()
                sys.exit(0)  # terminate program

            else:
                # invalid menu option
                print("invalid option.")

except Exception as e:
    # catch all exceptions silently (can be improved by logging)
    print(f"")
    # close socket on error or exit
    sock.close()
