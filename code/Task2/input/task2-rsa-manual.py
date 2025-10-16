import random
import math

# Student Number = s4015983; Message will be 4015983
message = 4015983

#prime number generator
def prime():

    isPrime = True

    num = random.randint(2, 1000)

    while not isPrime:
            
        if num == 2:
            print("ketemu anjing")
            break


        for i in range(3, int(math.sqrt(num)) + 1,2):
            if num % i == 0:
                num = num + 1
                print("not prime")
                continue
         
        else:
            isPrime = True
            break
    
    return num

#using prime function to generate prime number
P = prime()
Q = prime()

# generating prime number p and q
same = True 
while not same:

    # Checking if P and Q are the same
    # P and Q cannot be the same because it breaks the algorithm's security
    if P == Q:
        Q = prime()
    else:
        same = True
        
print({P})
print({Q})

# calculating n : p * q

N = P * Q

# calculating totient
TOTIENT = (P - 1) * (Q - 1)

# picking prime number e
# gcd of e and totient =1

def primeE(int):

    isPrime = True

    num = random.randint(1, TOTIENT)

    while not isPrime:
    

        for i in range(3, int(math.sqrt(num)) + 1,2):
            if num % i == 0:
                num = num + 1
                print("not prime")
                continue
         
        else:
            isPrime = True
            break
    
    return num

E = primeE(TOTIENT)

print({E})

# totient should not be divisible by e
# private key generator
# Encrption
# decryption



        