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

def modexp(base, exponent, modulus):
    # modular exponentiation implementation
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result

def to_bytes(x):
    # convert integer to bytes for hashing
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# rsa keys and dh params (unchanged)
n_alice = 4947663316723336381705441725100094160113818482878502536871596891255260315279973649033668692037752057410426470446128815188834847203907223565592625612283981344001002370062389720758780778439147499167157536217555875924935944594313654333312702372722031091091110749479809499467868527888186257246276904645964665623034683054341423401443059812119831778200838220496589556609214978274997933366993386651755711775370144430164088533148552806921866941525310585330243699303718962088022107680476740496398865458885117254177273835642895662554031614051272420332439990809050828709197769217427586487606145975205994864363924383582752642772301141361161019530079549737918797938456307516327174696234715893084953104611473671493329862389882048251108270766639826659485028545048203417263436921805981825640194700214358583418603076972136991795360885524826795327136108406608747390017890358671629171969953240453581234851735192516463016803798074298415079685580026361296861637642908143248924519424860206130706471487741988082769353269694050964551305332575832916614187114527895798396139177409677750459020959361740632240973022243522584303854804195585466085806867077367418148688649029430299930640711911212251993522493863275133775474556745057085838356338697119967620308401578901919683190183530964801465142246412746753528024028364809635309976091246591587372857873198654469154809936080436421217691718032499302999643780914281255062525562866344136844477625748126088907359407700188970689311470581970922752193252534033804534145315415815756597027097367878638378979160249660590441860942201723472223813005083505424286694787035568306068646849917350258131528631869413139913480694751241
e_alice = 65537
d_alice = int(os.environ["DEMO_RSA_PRIVATE_EXPONENT"])
n_bob = 362836421996182396690073851952474850907164210287413166356945463699154609426263469035563703148671656349832054800939181288975583294772284909460784043654558339965016659891438270899043538874014948757498249806566999207662840470529119851819374425660821825374655606440370027346930419286892514853646500584312157305588482929157300979113288636211473976635605839997450001064834152105080170461945184484630944882044396490861563138170648269182129603633938459362521569541224415967273506536285543852391085927251260736816293884260117790074697072316704115195585019153118702370008961562208425949871653397089256798844042894349798004780201
e_bob = 65537

p = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5AACAA68FFFFFFFFFFFFFFFF
""".replace("\n",""), 16)
g = 2

ID_A = "192.168.0.10"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.1.16', 5000))
print("[CLIENT] connected to server.")

def perform_handshake(sock, ID_A):
    # generate dh exponent and random nonce RA
    a = getRandomNBitInteger(2048)
    RA = get_random_bytes(32)
    A = modexp(g, a, p)

    # generate session iv for this handshake
    session_iv = get_random_bytes(16)
    print(f"[CLIENT] generated new session iv: {session_iv.hex()}")

    # send handshake data to server
    data = {
        'A': str(A),
        'RA': base64.b64encode(RA).decode(),
        'ID': ID_A,
        'IV': base64.b64encode(session_iv).decode()
    }
    sock.send(json.dumps(data).encode())

    # receive server handshake response
    sb_raw = sock.recv(8192)
    sb = json.loads(sb_raw.decode())
    B = int(sb['B'])
    RB = base64.b64decode(sb['RB'])
    ID_B = sb['ID']
    H_bytes = bytes.fromhex(sb['H'])
    Sig_B = int(sb['Sig'])

    # compute hash including iv and both nonces
    concat = to_bytes(A) + to_bytes(B) + RA + RB + ID_A.encode() + ID_B.encode() + session_iv
    H_check = hashlib.sha256(concat).digest()
    H_int = int.from_bytes(H_check, 'big')

    # verify server signature using bob's public key
    if modexp(Sig_B, e_bob, n_bob) != H_int or H_bytes != H_check:
        print("[CLIENT] bob authentication failed. terminating.")
        sock.close()
        sys.exit(1)
    print("[CLIENT] bob authentication succeeded.")

    # sign the hash with alice's private key and send
    Sig_A = modexp(H_int, d_alice, n_alice)
    sa = {'Sig': str(Sig_A)}
    sock.send(json.dumps(sa).encode())

    # compute shared secret and session key k
    shared = modexp(B, a, p)
    K = hashlib.sha256(to_bytes(shared)).digest()

    # print dh exponent, nonces, session key and iv for test case 1
    print(f"[CLIENT] dh exponent a: {a}")
    print(f"[CLIENT] session iv: {session_iv.hex()}")
    print("[CLIENT] bob authenticated to alice.")
    print("[CLIENT] alice authenticated to bob.")

    # destroy sensitive values
    a = None
    shared = None

    return K, session_iv

def encrypt_message(message, key, iv):
    # encrypt message with AES-cbc + padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message.encode(), AES.block_size))

def decrypt_message(ciphertext, key, iv):
    # decrypt message with AES-cbc + unpadding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def send_encrypted(conn, message, key, iv, label="CLIENT"):
    # encrypt and send message then print debug info
    ciphertext = encrypt_message(message, key, iv)
    print(f"[{label}] ciphertext: {ciphertext.hex()}")
    conn.sendall(ciphertext)
    print(f"[{label}] sending plaintext: {message}")

def receive_encrypted(conn, key, iv):
    # receive data and decrypt
    data = conn.recv(8192)
    decrypted = decrypt_message(data, key, iv)
    print(f"[CLIENT] decrypted plaintext: {decrypted}")
    return decrypted

print("[CLIENT] starting session")

try:
    while True:
        print("[CLIENT] starting handshake...")
        K, session_iv = perform_handshake(sock, ID_A)

        # start game session
        name = input("enter your name: ")
        send_encrypted(sock, name, K, session_iv)
        print(receive_encrypted(sock, K, session_iv))

        while True:
            menu = receive_encrypted(sock, K, session_iv)
            print(menu)
            choice = input(">> ")
            send_encrypted(sock, choice, K, session_iv)

            if choice == '1':
                print("[CLIENT] starting new round handshake...")
                # K, session_iv = perform_handshake(sock, ID_A)
                print(receive_encrypted(sock, K, session_iv))
                timed = input(">> ")
                send_encrypted(sock, timed, K, session_iv)
                print(receive_encrypted(sock, K, session_iv))
                level = input(">> ")
                send_encrypted(sock, level, K, session_iv)
                print(receive_encrypted(sock, K, session_iv))

                while True:
                    prompt = receive_encrypted(sock, K, session_iv)
                    print(prompt)
                    guess = input(">> ")
                    send_encrypted(sock, guess, K, session_iv)
                    result = receive_encrypted(sock, K, session_iv)
                    print(result)
                    if any(x in result for x in ["correct!", "time's up!", "too many invalid"]):
                        break

            elif choice == '2':
                board = receive_encrypted(sock, K, session_iv)
                print(board)
                action = input(">> ")
                send_encrypted(sock, action, K, session_iv)
                if action.upper() == 'D':
                    print(receive_encrypted(sock, K, session_iv))
                    name_to_delete = input(">> ")
                    send_encrypted(sock, name_to_delete, K, session_iv)
                    print(receive_encrypted(sock, K, session_iv))

            elif choice == '3':
                print(receive_encrypted(sock, K, session_iv))
                print(receive_encrypted(sock, K, session_iv))
                send_encrypted(sock, "\n", K, session_iv)

            elif choice == '4':
                print(receive_encrypted(sock, K, session_iv))
                sock.close()
                sys.exit(0)  # terminate program
            else:
                print("invalid option.")

except Exception as e:
    print(f"error: {e}")
    sock.close()
