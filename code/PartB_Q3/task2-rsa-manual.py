import random
import math

# Student Number = s4015983; Message will be 4015983
message = 4015983

# display message to be decrypted
print("Message to be decrypted: ", message)

# prime number generator
def prime():

    while True:
        # while it is true, will generate a random number
        num = random.randint(2, 1000)
        
        # checks if its a random number
        for i in range(2, int(math.sqrt(num)) + 1):
            if num % i == 0:
                break
         
        else:
            return num

# using prime function to generate prime number
P = prime()
Q = prime()

# checking if p and q are the same
same = True 
while same:

    # P and Q cannot be the same because it breaks the algorithm's security
    # if p and q is the same, generate a new prime number for q until it is not equal
    if P == Q:
        Q = prime()
    else:
        same = False

# displays keys
print("Public Key P: ", P)
print("Publice Key Q: ", Q)

# calculating 3rd public key N = p * q

N = P * Q

# prints n
print("Public Key N: ", N)

# calculating totient
TOTIENT = (P - 1) * (Q - 1)

# prints tottient
print("TOTIENT: ", TOTIENT)

# picking prime number e
# gcd of e and totient = 1 where e is 1<e<totient
def coprimeE(int):

    while True:
        num = random.randint(1, TOTIENT)

        if math.gcd(num, TOTIENT) == 1:
            return num

E = coprimeE(TOTIENT)

# prints the random prime selected
print("random prime: ", E)

# private key generator D using inverse mod modulo
D = pow(E, -1, TOTIENT)

# prints inverse modulo
print("inverse: ", D)

# Encrption of messahe using formula: m^e mod N
enc = pow(message, E) % N

# display encyrpted message
print("encrypted message ", enc)

# decryption of cipher using formula C^d mod N
dec =  pow(enc, D) % N

# display decrypted message 
print("decrypted message: ", dec)




        