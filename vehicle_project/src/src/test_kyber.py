from crypto import kyber

pk, sk = kyber.generate_keypair()

ciphertext, ss1 = kyber.encapsulate(pk)

ss2 = kyber.decapsulate(sk, ciphertext)

print(ss1 == ss2)

key1 = kyber.derive_session_key(ss1, "VehicleA")

key2 = kyber.derive_session_key(ss2, "VehicleA")

print(key1 == key2)