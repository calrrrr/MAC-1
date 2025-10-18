import random
import math

# Student Number = s4015983; Message will be 4015983
message = 4015983

print("Message to be decrypted: ", message)

#prime number generator
def prime():

    while True:
        num = random.randint(2, 1000)
            
        for i in range(2, int(math.sqrt(num)) + 1):
            if num % i == 0:
                break
         
        else:
            return num

#using prime function to generate prime number
P = prime()
Q = prime()

# generating random prime number p and q
same = True 
while same:

    # Checking if P and Q are the same
    # P and Q cannot be the same because it breaks the algorithm's security
    if P == Q:
        Q = prime()
    else:
        same = False
        
print("Public Key P: ", P)
print("Publice Key Q: ", Q)

# calculating public key N n : p * q

N = P * Q

print("Public Key N: ", N)

# calculating totient
TOTIENT = (P - 1) * (Q - 1)

print("TOTIENT: ", TOTIENT)

# picking prime number e
# gcd of e and totient = 1 where e is 1<e<totient

def coprimeE(int):

    while True:
        num = random.randint(1, TOTIENT)

        if math.gcd(num, TOTIENT) == 1:
            return num

E = coprimeE(TOTIENT)

print("random prime: ", E)

# private key generator D using inverse mod modulo

D = pow(E, -1, TOTIENT)

print("inverse: ", D)

# Encrption

enc = pow(message, E) % N

print("encrypted message ", enc)

# decryption

dec =  pow(enc, D) % N
print("decrypted message: ", dec)




        