import socket
import sys
import json
import base64
import hashlib
import random
import csv
import os
import time
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getRandomNBitInteger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def modexp(base, exponent, modulus):
    # perform modular exponentiation efficiently
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result

def to_bytes(x):
    # convert integer to bytes
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# rsa keys and dh params (unchanged)
n_bob = 362836421996182396690073851952474850907164210287413166356945463699154609426263469035563703148671656349832054800939181288975583294772284909460784043654558339965016659891438270899043538874014948757498249806566999207662840470529119851819374425660821825374655606440370027346930419286892514853646500584312157305588482929157300979113288636211473976635605839997450001064834152105080170461945184484630944882044396490861563138170648269182129603633938459362521569541224415967273506536285543852391085927251260736816293884260117790074697072316704115195585019153118702370008961562208425949871653397089256798844042894349798004780201
e_bob = 65537
d_bob = int(os.environ["DEMO_RSA_PRIVATE_EXPONENT"])
n_alice = 4947663316723336381705441725100094160113818482878502536871596891255260315279973649033668692037752057410426470446128815188834847203907223565592625612283981344001002370062389720758780778439147499167157536217555875924935944594313654333312702372722031091091110749479809499467868527888186257246276904645964665623034683054341423401443059812119831778200838220496589556609214978274997933366993386651755711775370144430164088533148552806921866941525310585330243699303718962088022107680476740496398865458885117254177273835642895662554031614051272420332439990809050828709197769217427586487606145975205994864363924383582752642772301141361161019530079549737918797938456307516327174696234715893084953104611473671493329862389882048251108270766639826659485028545048203417263436921805981825640194700214358583418603076972136991795360885524826795327136108406608747390017890358671629171969953240453581234851735192516463016803798074298415079685580026361296861637642908143248924519424860206130706471487741988082769353269694050964551305332575832916614187114527895798396139177409677750459020959361740632240973022243522584303854804195585466085806867077367418148688649029430299930640711911212251993522493863275133775474556745057085838356338697119967620308401578901919683190183530964801465142246412746753528024028364809635309976091246591587372857873198654469154809936080436421217691718032499302999643780914281255062525562866344136844477625748126088907359407700188970689311470581970922752193252534033804534145315415815756597027097367878638378979160249660590441860942201723472223813005083505424286694787035568306068646849917350258131528631869413139913480694751241
e_alice = 65537
p = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5AACAA68FFFFFFFFFFFFFFFF
""".replace("\n",""), 16)
g = 2

ID_B = '192.168.1.14'
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 5000

sock = socket.socket()
sock.bind((LISTEN_IP, LISTEN_PORT))
sock.listen(1)
print("[SERVER] listening on port", LISTEN_PORT)

conn, addr = sock.accept()
print(f"[SERVER] connection from {addr}")

leaderboard_file = "leaderboard.csv"
history_file = "history.txt"
leaderboard = {}

# load leaderboard from file if exists
if os.path.exists(leaderboard_file):
    with open(leaderboard_file, "r") as f:
        for row in csv.reader(f):
            if len(row) == 3:
                name, attempts, score = row
                leaderboard[name] = {"attempts": int(attempts), "score": int(score)}

# ensure history file exists
if not os.path.exists(history_file):
    open(history_file, 'w').close()

def append_to_profile(name, attempts, duration):
    # add game result entry to history file
    with open(history_file, "a") as f:
        f.write(f"{name} | attempts: {attempts} | time: {duration:.2f}s\n")

def read_profile():
    # read entire history file contents
    with open(history_file, "r") as f:
        return f.read()

def remove_leaderboard_entry(player):
    # remove player from leaderboard and update file
    if player in leaderboard:
        del leaderboard[player]
        with open(leaderboard_file, "w", newline='') as f:
            sorted_board = sorted(leaderboard.items(), key=lambda x: (x[1]["attempts"], -x[1]["score"]))
            csv.writer(f).writerows([[name, data["attempts"], data["score"]] for name, data in sorted_board])
        return True
    return False

def perform_handshake(conn, ID_B):
    # receive initial handshake data from client
    data1 = conn.recv(8192)
    init = json.loads(data1.decode())
    A  = int(init['A'])
    RA = base64.b64decode(init['RA'])
    ID_A = init['ID']
    session_iv = base64.b64decode(init['IV'])
    print(f"[SERVER] received session iv from client: {session_iv.hex()}")

    # generate server dh exponent b and compute B
    b = getRandomNBitInteger(2048)
    print(f"[SERVER] dh exponent b: {b}")
    B = modexp(g, b, p)

    # generate random nonce RB
    RB = get_random_bytes(32)

    # hash all handshake components including iv and nonces
    concat = to_bytes(A) + to_bytes(B) + RA + RB + ID_A.encode() + ID_B.encode() + session_iv
    H_bytes = hashlib.sha256(concat).digest()
    H_int = int.from_bytes(H_bytes, 'big')

    # sign the hash with bob's private key
    Sig_B = modexp(H_int, d_bob, n_bob)

    # prepare and send server handshake message
    SB = {
        'B': str(B),
        'RB': base64.b64encode(RB).decode(),
        'ID': ID_B,
        'H': H_bytes.hex(),
        'Sig': str(Sig_B)
    }
    conn.send(json.dumps(SB).encode())

    # receive client's signature and verify
    data2 = conn.recv(8192)
    sa = json.loads(data2.decode())
    Sig_A = int(sa['Sig'])

    if modexp(Sig_A, e_alice, n_alice) != H_int:
        print("[SERVER] alice authentication failed.")
        conn.close()
        sys.exit(1)
    print("[SERVER] alice authentication succeeded.")

    # compute shared dh secret and session key k
    shared = modexp(A, b, p)
    K = hashlib.sha256(to_bytes(shared)).digest()

    # print key, iv, and confirm authentication before destroying secrets
    print(f"[SERVER] session iv: {session_iv.hex()}")
    print("[SERVER] bob authenticated to alice.")
    print("[SERVER] alice authenticated to bob.")

    # destroy sensitive variables
    b = None
    shared = None

    return K, session_iv, ID_A

def encrypt_message(message, key, iv):
    # encrypt message using AES-cbc and pkcs7 padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message.encode(), AES.block_size))

def decrypt_message(ciphertext, key, iv):
    # decrypt message using AES-cbc and remove padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def send_encrypted(conn, message, key, iv, label="SERVER"):
    # encrypt and send message, then print ciphertext and plaintext logs
    ciphertext = encrypt_message(message, key, iv)
    print(f"[{label}] ciphertext: {ciphertext.hex()}")
    conn.sendall(ciphertext)
    print(f"[{label}] sending plaintext: {message}")

def receive_encrypted(conn, key, iv):
    # receive data, decrypt it, and print plaintext log
    data = conn.recv(8192)
    decrypted = decrypt_message(data, key, iv)
    print(f"[SERVER] decrypted plaintext: {decrypted}")
    return decrypted

print("[SERVER] starting session")

try:
    while True:
        print("[SERVER] waiting for handshake...")
        K, session_iv, ID_A = perform_handshake(conn, ID_B)

        while True:
            print("[SERVER] waiting for player name...")
            player_name = receive_encrypted(conn, K, session_iv).strip()
            print(f"[SERVER] player name received: {player_name}")

            send_encrypted(conn, f"welcome to the guessing game, {player_name}!", K, session_iv)
            total_score = leaderboard.get(player_name, {}).get("score", 0)

            while True:
                # send main menu with prompt for choice
                menu_msg = "\n--- menu ---\n1. start new game\n2. view leaderboard\n3. view history\n4. exit\nenter your choice:"
                send_encrypted(conn, menu_msg, K, session_iv)
                choice = receive_encrypted(conn, K, session_iv).strip()

                if choice == '4':
                    send_encrypted(conn, f"goodbye {player_name}!", K, session_iv)
                    break

                elif choice == '2':
                    # prepare leaderboard display message
                    board = sorted(leaderboard.items(), key=lambda x: (x[1]['attempts'], -x[1]['score']))
                    msg = "\nleaderboard:\n" + "\n".join([f"{i+1}. {n} - attempts: {d['attempts']}, score: {d['score']}" for i, (n, d) in enumerate(board)])
                    msg += "\noptions:\nd - delete an entry\nb - back to main menu\nenter your choice:"
                    send_encrypted(conn, msg, K, session_iv)

                    # get action for leaderboard
                    action = receive_encrypted(conn, K, session_iv).strip().upper()
                    if action == 'D':
                        send_encrypted(conn, "enter the name to delete:", K, session_iv)
                        del_name = receive_encrypted(conn, K, session_iv).strip()
                        if remove_leaderboard_entry(del_name):
                            send_encrypted(conn, f"{del_name} removed.", K, session_iv)
                        else:
                            send_encrypted(conn, f"{del_name} not found.", K, session_iv)

                elif choice == '3':
                    # send game history and wait for user to return
                    history = read_profile()
                    send_encrypted(conn, "\ngame history:\n" + (history if history else "no history yet."), K, session_iv)
                    send_encrypted(conn, "press enter to return...", K, session_iv)
                    receive_encrypted(conn, K, session_iv)

                elif choice == '1':
                    # start new game round with fresh handshake for keys
                    print("[SERVER] starting new game round handshake for fresh keys...")
                    # K, session_iv, _ = perform_handshake(conn, ID_B)

                    send_encrypted(conn, "enable timed mode? (y/n):", K, session_iv)
                    timed = receive_encrypted(conn, K, session_iv).lower() == 'y'

                    send_encrypted(conn, "choose difficulty: 1. easy (1-50), 2. medium (1-100), 3. hard (1-200):", K, session_iv)
                    level = receive_encrypted(conn, K, session_iv)
                    max_range = {'1': 50, '2': 100, '3': 200}.get(level, 100)
                    number = random.randint(1, max_range)
                    send_encrypted(conn, f"i picked a number between 1 and {max_range}. start guessing!", K, session_iv)

                    attempts, invalid = 0, 0
                    start = time.time()

                    while True:
                        send_encrypted(conn, "enter your guess:", K, session_iv)
                        guess = receive_encrypted(conn, K, session_iv)

                        if timed and time.time() - start > 30:
                            send_encrypted(conn, "time's up!", K, session_iv)
                            break

                        if not guess.isdigit() or not (1 <= int(guess) <= max_range):
                            send_encrypted(conn, "invalid input.", K, session_iv)
                            invalid += 1
                            if invalid >= 10:
                                send_encrypted(conn, "too many invalid inputs.", K, session_iv)
                                break
                            continue

                        guess = int(guess)
                        attempts += 1

                        if guess < number:
                            hint = "you're burning hot!" if number - guess <= 5 else "you're warm." if number - guess <= 10 else "you're cold."
                            send_encrypted(conn, f"higher. {hint}", K, session_iv)
                        elif guess > number:
                            hint = "you're burning hot!" if guess - number <= 5 else "you're warm." if guess - number <= 10 else "you're cold."
                            send_encrypted(conn, f"lower. {hint}", K, session_iv)
                        else:
                            duration = time.time() - start
                            msg = f"correct! attempts: {attempts}, time: {duration:.2f}s"
                            append_to_profile(player_name, attempts, duration)
                            score = max(0, 10 - attempts)
                            total_score += score
                            leaderboard[player_name] = {
                                "attempts": min(attempts, leaderboard.get(player_name, {}).get("attempts", attempts)),
                                "score": total_score
                            }
                            with open(leaderboard_file, "w", newline='') as f:
                                writer = csv.writer(f)
                                for name, data in sorted(leaderboard.items(), key=lambda x: (x[1]["attempts"], -x[1]["score"])):
                                    writer.writerow([name, data["attempts"], data["score"]])
                            msg += f"\nscore this round: {score}, total: {total_score}"
                            send_encrypted(conn, msg, K, session_iv)
                            break

                else:
                    send_encrypted(conn, "invalid option.", K, session_iv)

except Exception as e:
    print(f"")
finally:
    conn.close()
    sock.close()
    print("[SERVER] connection closed.")
