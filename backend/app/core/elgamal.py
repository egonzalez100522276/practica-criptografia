import random
import hashlib

# Standard parameters for educational purposes (NOT SECURE for production)
# Using a small prime for demonstration or a larger one if possible. 
# For this exercise, we'll use a reasonably sized prime to keep it fast but "real".
# RFC 3526 2048-bit MODP Group (Just the prime part, simplified)
# Actually, for ElGamal signatures, we need a prime p and a generator g.
# Let's use a smaller prime to ensure performance in this python implementation without GMP.
# But large enough to not be trivial.
# Let's use a generated safe prime or a known one. 
# For simplicity and speed in this context, we will use a 1024-bit prime from RFC 5114 or similar, 
# or just generate a smaller one if we want to be self-contained.
# Let's stick to a fixed set of parameters for all users to make verification easier.

# Using a standard safe prime (Sophie Germain prime based) would be best.
# Let's use a 2048-bit prime from RFC 3526 Group 14.
# It's huge for pure python math but Python handles large integers automatically.
# P = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
# That's too complex to hardcode.

# Let's use a smaller prime for this assignment to ensure it runs smoothly in the dev environment.
# 4096-bit is standard but slow in pure python for key gen if we did it from scratch.
# We will use fixed parameters.

# P = 23 (Example small prime) -> NO, too small.
# Let's generate a random prime or use a fixed one.
# We will use a fixed large prime for the system.

# P and G for the group.
# P should be a large prime.
# G should be a generator of the multiplicative group of integers modulo P.

# Let's use a 1024-bit prime.
P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
P = int(P_HEX, 16)
G = 2

def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of a modulo m.
    a * x = 1 (mod m)
    """
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        # q is quotient
        q = a // m
        t = m
        # m is remainder now, process same as Euclid's algo
        m = a % m
        a = t
        t = y
        # Update y and x
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x

def generate_keys():
    """
    Generates an ElGamal key pair.
    Returns:
        public_key: (P, G, y) where y = G^x mod P
        private_key: x
    """
    # Private key x should be random in [1, P-2]
    x = random.randint(1, P - 2)
    y = pow(G, x, P)
    
    public_key = (P, G, y)
    private_key = x
    return public_key, private_key

def sign(message: str, private_key: int):
    """
    Signs a message using ElGamal signature scheme.
    Message is hashed first.
    Returns (r, s)
    """
    # 1. Hash the message
    h = hashlib.sha256(message.encode()).hexdigest()
    m = int(h, 16)
    
    # 2. Choose a random k such that 1 < k < P-1 and gcd(k, P-1) = 1
    p_minus_1 = P - 1
    while True:
        k = random.randint(2, p_minus_1 - 1)
        if mod_inverse(k, p_minus_1) is not None:
             # Check gcd is 1 by trying to compute inverse. 
             # Actually mod_inverse assumes gcd is 1, let's use math.gcd
             import math
             if math.gcd(k, p_minus_1) == 1:
                 break
    
    # 3. Compute r = g^k mod P
    r = pow(G, k, P)
    
    # 4. Compute s = (m - x*r) * k^-1 mod (P-1)
    k_inv = mod_inverse(k, p_minus_1)
    x = private_key
    
    s = (k_inv * (m - x * r)) % p_minus_1
    
    return r, s

def verify(message: str, signature: tuple[int, int], public_key_y: int) -> bool:
    """
    Verifies an ElGamal signature.
    """
    r, s = signature
    if not (0 < r < P) or not (0 < s < P - 1):
        return False
        
    h = hashlib.sha256(message.encode()).hexdigest()
    m = int(h, 16)
    
    # Verify: (g^m) mod P == (y^r * r^s) mod P
    lhs = pow(G, m, P)
    rhs = (pow(public_key_y, r, P) * pow(r, s, P)) % P
    
    return lhs == rhs
