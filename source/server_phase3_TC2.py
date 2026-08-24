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

# modular exponentiation function for efficient calculation of (base^exponent) mod modulus
def modexp(base, exponent, modulus):
    # initialize result to 1 (identity for multiplication)
    result = 1
    # reduce base modulo modulus before starting
    base = base % modulus
    # loop until exponent becomes zero
    while exponent > 0:
        # if least significant bit of exponent is 1, multiply result by base mod modulus
        if exponent & 1:
            result = (result * base) % modulus
        # right shift exponent by 1 bit (divide by 2)
        exponent >>= 1
        # square base mod modulus for next iteration
        base = (base * base) % modulus
    # return the final modular exponentiation result
    return result

# helper function to convert integer to bytes in big endian order
def to_bytes(x):
    # calculate minimum number of bytes needed and convert
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

# rsa keys and diffie-hellman parameters (unchanged)

# bob's rsa modulus n and public exponent e
n_bob = 362836421996182396690073851952474850907164210287413166356945463699154609426263469035563703148671656349832054800939181288975583294772284909460784043654558339965016659891438270899043538874014948757498249806566999207662840470529119851819374425660821825374655606440370027346930419286892514853646500584312157305588482929157300979113288636211473976635605839997450001064834152105080170461945184484630944882044396490861563138170648269182129603633938459362521569541224415967273506536285543852391085927251260736816293884260117790074697072316704115195585019153118702370008961562208425949871653397089256798844042894349798004780201
e_bob = 65537

# *** this is the "wrong" private key for test case 2 (simulate trudy posing as bob) ***
d_bob = 1234567890123456789012345678901234567890123456789012345678901234567890

# alice's rsa modulus n and public exponent e
n_alice = 4947663316723336381705441725100094160113818482878502536871596891255260315279973649033668692037752057410426470446128815188834847203907223565592625612283981344001002370062389720758780778439147499167157536217555875924935944594313654333312702372722031091091110749479809499467868527888186257246276904645964665623034683054341423401443059812119831778200838220496589556609214978274997933366993386651755711775370144430164088533148552806921866941525310585330243699303718962088022107680476740496398865458885117254177273835642895662554031614051272420332439990809050828709197769217427586487606145975205994864363924383582752642772301141361161019530079549737918797938456307516327174696234715893084953104611473671493329862389882048251108270766639826659485028545048203417263436921805981825640194700214358583418603076972136991795360885524826795327136108406608747390017890358671629171969953240453581234851735192516463016803798074298415079685580026361296861637642908143248924519424860206130706471487741988082769353269694050964551305332575832916614185286988190465
e_alice = 65537

# diffie-hellman prime p (2048-bit prime from RFC 3526)
p = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5AACAA68FFFFFFFFFFFFFFFF
""".replace("\n",""), 16)
# diffie-hellman generator g
g = 2

# server id (ip)
ID_B = '192.168.1.14'
# server listen ip and port (listen on all interfaces)
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 5000

# create socket object for server
sock = socket.socket()
# bind socket to ip and port
sock.bind((LISTEN_IP, LISTEN_PORT))
# listen for one incoming connection
sock.listen(1)
print("[server] listening on port", LISTEN_PORT)

# accept incoming client connection
conn, addr = sock.accept()
print(f"[server] connection from {addr}")

# filenames for leaderboard and history data
leaderboard_file = "leaderboard.csv"
history_file = "history.txt"
# initialize leaderboard dictionary
leaderboard = {}

# if leaderboard file exists, load its content into leaderboard dictionary
if os.path.exists(leaderboard_file):
    with open(leaderboard_file, "r") as f:
        for row in csv.reader(f):
            # each row expected to have name, attempts, score
            if len(row) == 3:
                name, attempts, score = row
                leaderboard[name] = {"attempts": int(attempts), "score": int(score)}

# if history file does not exist, create empty file
if not os.path.exists(history_file):
    open(history_file, 'w').close()

# function to append a new game result to history file
def append_to_profile(name, attempts, duration):
    with open(history_file, "a") as f:
        # write formatted string with player name, attempts, and time taken
        f.write(f"{name} | Attempts: {attempts} | Time: {duration:.2f}s\n")

# function to read entire history file content
def read_profile():
    with open(history_file, "r") as f:
        return f.read()

# function to remove a player entry from leaderboard dictionary and file
def remove_leaderboard_entry(player):
    # check if player exists in leaderboard dictionary
    if player in leaderboard:
        # delete player entry from dictionary
        del leaderboard[player]
        # rewrite leaderboard file with updated entries, sorted by attempts ascending and score descending
        with open(leaderboard_file, "w", newline='') as f:
            sorted_board = sorted(leaderboard.items(), key=lambda x: (x[1]["attempts"], -x[1]["score"]))
            csv.writer(f).writerows([[name, data["attempts"], data["score"]] for name, data in sorted_board])
        # return true indicating deletion succeeded
        return True
    # return false if player not found
    return False

# perform handshake function implementing diffie-hellman key exchange and mutual authentication
def perform_handshake(conn, ID_B):
    # receive initial handshake message from client (json string)
    data1 = conn.recv(8192)
    init = json.loads(data1.decode())
    # extract client's dh public value A (int)
    A  = int(init['A'])
    # extract client's random challenge RA (bytes)
    RA = base64.b64decode(init['RA'])
    # extract client id string
    ID_A = init['ID']
    # extract session iv from client (bytes)
    session_iv = base64.b64decode(init['IV'])
    print(f"[server] received session iv from client: {session_iv.hex()}")

    # generate server's private dh exponent b (random 2048-bit int)
    b = getRandomNBitInteger(2048)
    print(f"[server] bob's dh exponent b: {b}")

    # compute server's dh public value B = g^b mod p
    B = modexp(g, b, p)
    # generate server's random challenge RB (32 bytes)
    RB = get_random_bytes(32)

    # concatenate values for hashing: A, B, RA, RB, IDs, session iv
    concat = to_bytes(A) + to_bytes(B) + RA + RB + ID_A.encode() + ID_B.encode() + session_iv
    # hash concatenated bytes with sha256
    H_bytes = hashlib.sha256(concat).digest()
    H_int = int.from_bytes(H_bytes, 'big')
    # sign hash with server's private key d_bob using modular exponentiation
    Sig_B = modexp(H_int, d_bob, n_bob)

    # prepare handshake response dictionary with B, RB, ID, hash, signature
    SB = {
        'B': str(B),
        'RB': base64.b64encode(RB).decode(),
        'ID': ID_B,
        'H': H_bytes.hex(),
        'Sig': str(Sig_B)
    }
    # send handshake response to client as json string
    conn.send(json.dumps(SB).encode())

    # receive client's signature on hash (json)
    data2 = conn.recv(8192)
    sa = json.loads(data2.decode())
    Sig_A = int(sa['Sig'])

    # verify client's signature by decrypting with alice's public key and comparing hash
    if modexp(Sig_A, e_alice, n_alice) != H_int:
        print("[server] alice authentication failed.")
        # close connection and exit program on failed authentication
        conn.close()
        sys.exit(1)
    print("[server] alice authentication succeeded.")

    # compute shared dh secret = A^b mod p
    shared = modexp(A, b, p)
    # derive session key K by hashing shared secret with sha256
    K = hashlib.sha256(to_bytes(shared)).digest()

    # clear sensitive variables
    b = None
    shared = None

    # return session key, session iv, and client id for further use
    return K, session_iv, ID_A

# encrypt plaintext message using aes-256-cbc with provided key and iv
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # pad message and encrypt, returning ciphertext bytes
    return cipher.encrypt(pad(message.encode(), AES.block_size))

# decrypt ciphertext message using aes-256-cbc with provided key and iv
def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # decrypt and unpad ciphertext to return plaintext string
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# send encrypted message over connection and print debug info
def send_encrypted(conn, message, key, iv, label="SERVER"):
    ciphertext = encrypt_message(message, key, iv)
    print(f"[{label}] ciphertext: {ciphertext.hex()}")
    conn.sendall(ciphertext)
    print(f"[{label}] sending plaintext: {message}")

# receive encrypted message from connection and decrypt it
def receive_encrypted(conn, key, iv):
    data = conn.recv(8192)
    decrypted = decrypt_message(data, key, iv)
    print(f"[server] decrypted plaintext: {decrypted}")
    return decrypted

print("[server] starting session")

try:
    # main server loop waiting for handshake and interacting with client
    while True:
        print("[server] waiting for handshake...")
        # perform handshake and get session key, iv, and client id
        K, session_iv, ID_A = perform_handshake(conn, ID_B)

        while True:
            print("[server] waiting for player name...")
            # receive encrypted player name and strip whitespace
            player_name = receive_encrypted(conn, K, session_iv).strip()
            print(f"[server] player name received: {player_name}")

            # send welcome message encrypted
            send_encrypted(conn, f"welcome to the guessing game, {player_name}!", K, session_iv)
            # get player's total score from leaderboard or 0 if new
            total_score = leaderboard.get(player_name, {}).get("score", 0)

            while True:
                # send main menu encrypted
                send_encrypted(conn, "\n--- menu ---\n1. start new game\n2. view leaderboard\n3. view history\n4. exit\nenter your choice:", K, session_iv)
                # receive menu choice encrypted and strip whitespace
                choice = receive_encrypted(conn, K, session_iv).strip()

                if choice == '4':
                    # exit option: send goodbye message and break to wait for new handshake
                    send_encrypted(conn, f"goodbye {player_name}!", K, session_iv)
                    break

                elif choice == '2':
                    # display leaderboard sorted by attempts ascending and score descending
                    board = sorted(leaderboard.items(), key=lambda x: (x[1]['attempts'], -x[1]['score']))
                    # prepare leaderboard message string
                    msg = "\nleaderboard:\n" + "\n".join([f"{i+1}. {n} - attempts: {d['attempts']}, score: {d['score']}" for i, (n, d) in enumerate(board)])
                    msg += "\noptions:\nd - delete an entry\nb - back to main menu"
                    send_encrypted(conn, msg, K, session_iv)
                    # receive action choice encrypted and convert to uppercase
                    action = receive_encrypted(conn, K, session_iv).strip().upper()
                    if action == 'D':
                        # send prompt for name to delete
                        send_encrypted(conn, "enter the name to delete:", K, session_iv)
                        # receive name to delete encrypted
                        del_name = receive_encrypted(conn, K, session_iv).strip()
                        # attempt to remove entry and send result message
                        if remove_leaderboard_entry(del_name):
                            send_encrypted(conn, f"{del_name} removed.", K, session_iv)
                        else:
                            send_encrypted(conn, f"{del_name} not found.", K, session_iv)

                elif choice == '3':
                    # view game history: send history contents
                    history = read_profile()
                    send_encrypted(conn, "\ngame history:\n" + (history if history else "no history yet."), K, session_iv)
                    # send prompt to press enter to return
                    send_encrypted(conn, "press enter to return...", K, session_iv)
                    # receive confirmation from client (not used)
                    receive_encrypted(conn, K, session_iv)

                elif choice == '1':
                    # start new game round: perform handshake for fresh keys
                    print("[server] starting new game round handshake for fresh keys...")
                    K, session_iv, _ = perform_handshake(conn, ID_B)

                    # ask client if timed mode enabled
                    send_encrypted(conn, "enable timed mode? (y/n):", K, session_iv)
                    timed = receive_encrypted(conn, K, session_iv).lower() == 'y'
                    # ask for difficulty level
                    send_encrypted(conn, "choose difficulty: 1. easy (1-50), 2. medium (1-100), 3. hard (1-200):", K, session_iv)
                    level = receive_encrypted(conn, K, session_iv)
                    # set max range based on difficulty
                    max_range = {'1': 50, '2': 100, '3': 200}.get(level, 100)
                    # pick a random number in range
                    number = random.randint(1, max_range)
                    # notify client to start guessing
                    send_encrypted(conn, f"i picked a number between 1 and {max_range}. start guessing!", K, session_iv)

                    # initialize attempts and invalid input counters
                    attempts, invalid = 0, 0
                    # start timer
                    start = time.time()

                    while True:
                        # prompt client for guess
                        send_encrypted(conn, "enter your guess:", K, session_iv)
                        # receive guess
                        guess = receive_encrypted(conn, K, session_iv)

                        # if timed mode and time exceeded 30 seconds, end round
                        if timed and time.time() - start > 30:
                            send_encrypted(conn, "time's up!", K, session_iv)
                            break

                        # validate guess input
                        if not guess.isdigit() or not (1 <= int(guess) <= max_range):
                            send_encrypted(conn, "invalid input.", K, session_iv)
                            invalid += 1
                            # if too many invalid inputs, end round
                            if invalid >= 10:
                                send_encrypted(conn, "too many invalid inputs.", K, session_iv)
                                break
                            continue

                        guess = int(guess)
                        attempts += 1

                        # provide hints based on guess proximity
                        if guess < number:
                            hint = "you're burning hot!" if number - guess <= 5 else "you're warm." if number - guess <= 10 else "you're cold."
                            send_encrypted(conn, f"higher. {hint}", K, session_iv)
                        elif guess > number:
                            hint = "you're burning hot!" if guess - number <= 5 else "you're warm." if guess - number <= 10 else "you're cold."
                            send_encrypted(conn, f"lower. {hint}", K, session_iv)
                        else:
                            # correct guess: calculate duration and update leaderboard and history
                            duration = time.time() - start
                            msg = f"correct! attempts: {attempts}, time: {duration:.2f}s"
                            append_to_profile(player_name, attempts, duration)
                            # calculate score based on attempts
                            score = max(0, 10 - attempts)
                            total_score += score
                            # update leaderboard entry
                            leaderboard[player_name] = {
                                "attempts": min(attempts, leaderboard.get(player_name, {}).get("attempts", attempts)),
                                "score": total_score
                            }
                            # write updated leaderboard to file sorted by attempts asc and score desc
                            with open(leaderboard_file, "w", newline='') as f:
                                writer = csv.writer(f)
                                for name, data in sorted(leaderboard.items(), key=lambda x: (x[1]["attempts"], -x[1]["score"])):
                                    writer.writerow([name, data["attempts"], data["score"]])
                            msg += f"\nscore this round: {score}, total: {total_score}"
                            send_encrypted(conn, msg, K, session_iv)
                            break

                else:
                    # invalid menu option received, send invalid option message
                    send_encrypted(conn, "invalid option.", K, session_iv)

except Exception as e:
    # silent exception handling (can be improved to log errors)
    print(f"")
finally:
    # clean up by closing connection and socket
    conn.close()
    sock.close()
    print("[server] connection closed.")
