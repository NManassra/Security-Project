# client.py
import socket
import sys
import json
import base64
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getRandomNBitInteger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# function to perform modular exponentiation efficiently
def modexp(base, exponent, modulus):
    # initialize result to 1 (multiplicative identity)
    result = 1
    # reduce base modulo modulus initially
    base = base % modulus
    # loop while exponent is greater than zero
    while exponent > 0:
        # if least significant bit of exponent is 1, multiply result by base modulo modulus
        if exponent & 1:
            result = (result * base) % modulus
        # right shift exponent by 1 bit (divide by 2)
        exponent >>= 1
        # square base modulo modulus for next iteration
        base = (base * base) % modulus
    # return final modular exponentiation result
    return result

# helper function to convert integer to bytes (big endian)
def to_bytes(x):
    # calculate minimum number of bytes required and convert
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# rsa keys and diffie-hellman parameters for alice (client) and bob (server)

# alice's rsa modulus (n), public exponent (e)
n_alice = 4947663316723336381705441725100094160113818482878502536871596891255260315279973649033668692037752057410426470446128815188834847203907223565592625612283981344001002370062389720758780778439147499167157536217555875924935944594313654333312702372722031091091110749479809499467868527888186257246276904645964665623034683054341423401443059812119831778200838220496589556609214978274997933366993386651755711775370144430164088533148552806921866941525310585330243699303718962088022107680476740496398865458885117254177273835642895662554031614051272420332439990809050828709197769217427586487606145975205994864363924383582752642772301141361161019530079549737918797938456307516327174696234715893084953104611473671493329862389882048251108270766639826659485028545048203417263436921805981825640194700214358583418603076972136991795360885524826795327136108406608747390017890358671629171969953240453581234851735192516463016803798074298415079685580026361296861637642908143248924519424860206130706471487741988082769353269694050964551305332575832916614185286988190465
e_alice = 65537
# change d_alice to a wrong value to simulate test case 3 (trudy posing as alice)
d_alice = 1234567890123456789012345678901234567890  # invalid private key to force authentication failure

# bob's rsa modulus (n) and public exponent (e)
n_bob = 362836421996182396690073851952474850907164210287413166356945463699154609426263469035563703148671656349832054800939181288975583294772284909460784043654558339965016659891438270899043538874014948757498249806566999207662840470529119851819374425660821825374655606440370027346930419286892514853646500584312157305588482929157300979113288636211473976635605839997450001064834152105080170461945184484630944882044396490861563138170648269182129603633938459362521569541224415967273506536285543852391085927251260736816293884260117790074697072316704115195585019153118702370008961562208425949871653397089256798844042894349798004780201
e_bob = 65537

# diffie-hellman prime modulus p from RFC3526 (2048 bits)
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

# create a socket and connect to server at ip 192.168.1.16 and port 5000
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.1.16', 5000))
print("[client] connected to server.")

# perform handshake function implementing dh key exchange and mutual authentication
def perform_handshake(sock, ID_A):
    # generate client's private diffie-hellman exponent a (random 2048-bit int)
    a = getRandomNBitInteger(2048)
    print(f"[client] exponent a selected: {a}")  # print chosen exponent a for debug

    # generate client's random challenge RA (32 random bytes)
    RA = get_random_bytes(32)
    # compute client's dh public value A = g^a mod p
    A = modexp(g, a, p)
    # generate session iv for aes encryption (16 bytes random)
    session_iv = get_random_bytes(16)
    print(f"[client] generated new session iv: {session_iv.hex()}")

    # prepare handshake message data dictionary
    data = {
        'A': str(A),  # client's dh public value as string
        'RA': base64.b64encode(RA).decode(),  # base64 encoded client random challenge
        'ID': ID_A,  # client id string
        'IV': base64.b64encode(session_iv).decode()  # base64 encoded session iv for aes
    }
    # send handshake initiation message as json string to server
    sock.send(json.dumps(data).encode())

    # receive server's handshake response message (json string)
    sb_raw = sock.recv(8192)
    sb = json.loads(sb_raw.decode())

    # extract server's dh public value B (int)
    B = int(sb['B'])
    # extract server's challenge RB (random bytes)
    RB = base64.b64decode(sb['RB'])
    # extract server's id string
    ID_B = sb['ID']
    # extract server's hash H (bytes)
    H_bytes = bytes.fromhex(sb['H'])
    # extract server's signature on H (int)
    Sig_B = int(sb['Sig'])

    # recompute hash H over concatenated values: A, B, RA, RB, IDs and session_iv
    concat = to_bytes(A) + to_bytes(B) + RA + RB + ID_A.encode() + ID_B.encode() + session_iv
    H_check = hashlib.sha256(concat).digest()
    H_int = int.from_bytes(H_check, 'big')

    # verify server's signature by decrypting Sig_B with bob's public key and checking hash equality
    if modexp(Sig_B, e_bob, n_bob) != H_int or H_bytes != H_check:
        # if verification fails, print message and close connection then exit
        print("[client] bob authentication failed. terminating.")
        sock.close()
        sys.exit(1)
    print("[client] bob authentication succeeded.")

    # sign hash H with client's private key d_alice (using modular exponentiation)
    Sig_A = modexp(H_int, d_alice, n_alice)
    # prepare signature message dictionary
    sa = {'Sig': str(Sig_A)}
    # send signature to server as json
    sock.send(json.dumps(sa).encode())

    # compute shared dh secret = B^a mod p
    shared = modexp(B, a, p)
    # derive session key K by hashing shared secret with sha256
    K = hashlib.sha256(to_bytes(shared)).digest()

    # clear sensitive variables
    a = None
    shared = None

    # return session key and iv for encrypting further communication
    return K, session_iv

# encrypt a message using aes-256-cbc with given key and iv
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # pad plaintext and encrypt to ciphertext bytes
    return cipher.encrypt(pad(message.encode(), AES.block_size))

# decrypt a ciphertext message using aes-256-cbc with given key and iv
def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # decrypt and unpad to get plaintext string
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# send encrypted message over socket and print debug info
def send_encrypted(conn, message, key, iv, label="client"):
    ciphertext = encrypt_message(message, key, iv)
    print(f"[{label}] ciphertext: {ciphertext.hex()}")  # print hex of ciphertext
    conn.sendall(ciphertext)  # send encrypted bytes over socket
    print(f"[{label}] sending plaintext: {message}")  # print plaintext message

# receive encrypted message from socket and decrypt it
def receive_encrypted(conn, key, iv):
    data = conn.recv(8192)
    decrypted = decrypt_message(data, key, iv)
    print(f"[client] decrypted plaintext: {decrypted}")  # print decrypted message
    return decrypted

print("[client] starting session")

try:
    # main client loop to handshake and interact with server
    while True:
        print("[client] starting handshake...")
        # perform handshake to establish session key and iv
        K, session_iv = perform_handshake(sock, ID_A)

        # prompt user to enter name and send encrypted to server
        name = input("enter your name: ")
        send_encrypted(sock, name, K, session_iv)
        # receive welcome message from server and print
        print(receive_encrypted(sock, K, session_iv))

        while True:
            # receive encrypted menu from server and print
            menu = receive_encrypted(sock, K, session_iv)
            print(menu)
            # get user menu choice input
            choice = input(">> ")
            # send encrypted choice to server
            send_encrypted(sock, choice, K, session_iv)

            if choice == '1':
                # start new round, perform handshake again to get fresh keys
                print("[client] starting new round handshake...")
                K, session_iv = perform_handshake(sock, ID_A)
                # receive prompt from server and print
                print(receive_encrypted(sock, K, session_iv))
                # get user input for timed mode and send
                timed = input(">> ")
                send_encrypted(sock, timed, K, session_iv)
                # receive confirmation and print
                print(receive_encrypted(sock, K, session_iv))
                # get difficulty level input and send
                level = input(">> ")
                send_encrypted(sock, level, K, session_iv)
                # receive confirmation and print
                print(receive_encrypted(sock, K, session_iv))

                while True:
                    # receive guess prompt and print
                    prompt = receive_encrypted(sock, K, session_iv)
                    print(prompt)
                    # get user guess input and send
                    guess = input(">> ")
                    send_encrypted(sock, guess, K, session_iv)
                    # receive result and print
                    result = receive_encrypted(sock, K, session_iv)
                    print(result)
                    # break loop if game round ended (correct or time's up or invalid inputs)
                    if any(x in result for x in ["correct!", "time's up!", "too many invalid"]):
                        break

            elif choice == '2':
                # view leaderboard, receive and print it
                board = receive_encrypted(sock, K, session_iv)
                print(board)
                # get action input and send
                action = input(">> ")
                send_encrypted(sock, action, K, session_iv)
                if action.upper() == 'D':
                    # receive prompt for delete name and print
                    print(receive_encrypted(sock, K, session_iv))
                    # get name to delete and send
                    name_to_delete = input(">> ")
                    send_encrypted(sock, name_to_delete, K, session_iv)
                    # receive result and print
                    print(receive_encrypted(sock, K, session_iv))

            elif choice == '3':
                # view history, receive and print
                print(receive_encrypted(sock, K, session_iv))
                print(receive_encrypted(sock, K, session_iv))
                # send blank to return
                send_encrypted(sock, "\n", K, session_iv)

            elif choice == '4':
                # exit game, receive goodbye message and print
                print(receive_encrypted(sock, K, session_iv))
                # close socket and exit client program
                sock.close()
                sys.exit(0)

            else:
                # invalid menu option, print error message locally
                print("invalid option.")

except Exception as e:
    # handle exceptions silently (could be improved for debugging)
    print(f"")
    sock.close()
