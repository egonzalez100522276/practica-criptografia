/**
 * ElGamal Digital Signature Implementation in TypeScript
 * 
 * This is a port of the Python implementation for client-side signing.
 * Uses the same parameters (P, G) as the backend for compatibility.
 */

// Same 1024-bit prime from backend (RFC 3526 Group 14)
const P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
const P = BigInt("0x" + P_HEX);
const G = 2n;

/**
 * Compute modular multiplicative inverse using Extended Euclidean Algorithm
 */
function modInverse(a: bigint, m: bigint): bigint {
  let m0 = m;
  let y = 0n;
  let x = 1n;

  if (m === 1n) return 0n;

  while (a > 1n) {
    const q = a / m;
    let t = m;
    m = a % m;
    a = t;
    t = y;
    y = x - q * y;
    x = t;
  }

  if (x < 0n) x = x + m0;
  return x;
}

/**
 * Compute SHA-256 hash of a string and return as bigint
 */
async function hashToBigInt(message: string): Promise<bigint> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return BigInt("0x" + hashHex);
}

/**
 * Generate ElGamal key pair
 * Returns: { publicKey: { P, G, y }, privateKey: x }
 */
export function generateKeys(): { publicKey: { P: bigint; G: bigint; y: bigint }; privateKey: bigint } {
  // Generate random private key x in range [1, P-2]
  const x = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) % (P - 2n) + 1n;
  
  // Compute public key y = G^x mod P
  const y = modPow(G, x, P);
  
  return {
    publicKey: { P, G, y },
    privateKey: x
  };
}

/**
 * Modular exponentiation: (base^exp) mod m
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  
  return result;
}

/**
 * GCD using Euclidean algorithm
 */
function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a;
}

/**
 * Sign a message using ElGamal signature scheme
 * Returns: { r, s }
 */
export async function sign(message: string, privateKey: bigint): Promise<{ r: bigint; s: bigint }> {
  const m = await hashToBigInt(message);
  const pMinus1 = P - 1n;
  
  // Choose random k such that gcd(k, P-1) = 1
  let k: bigint;
  do {
    k = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)) % (pMinus1 - 2n) + 2n;
  } while (gcd(k, pMinus1) !== 1n);
  
  // Compute r = G^k mod P
  const r = modPow(G, k, P);
  
  // Compute s = (m - x*r) * k^-1 mod (P-1)
  const kInv = modInverse(k, pMinus1);
  const x = privateKey;
  
  let s = ((m - x * r) % pMinus1) * kInv % pMinus1;
  if (s < 0n) s = s + pMinus1;
  
  return { r, s };
}

/**
 * Verify an ElGamal signature
 */
export async function verify(message: string, signature: { r: bigint; s: bigint }, publicKeyY: bigint): Promise<boolean> {
  const { r, s } = signature;
  
  // Check bounds
  if (r <= 0n || r >= P || s <= 0n || s >= P - 1n) {
    return false;
  }
  
  const m = await hashToBigInt(message);
  
  // Verify: G^m mod P == (y^r * r^s) mod P
  const lhs = modPow(G, m, P);
  const rhs = (modPow(publicKeyY, r, P) * modPow(r, s, P)) % P;
  
  return lhs === rhs;
}

/**
 * Serialize ElGamal public key to JSON string (for storage/transmission)
 */
export function serializePublicKey(publicKey: { P: bigint; G: bigint; y: bigint }): string {
  return JSON.stringify([
    publicKey.P.toString(),
    publicKey.G.toString(),
    publicKey.y.toString()
  ]);
}

/**
 * Deserialize ElGamal public key from JSON string
 */
export function deserializePublicKey(json: string): { P: bigint; G: bigint; y: bigint } {
  const [pStr, gStr, yStr] = JSON.parse(json);
  return {
    P: BigInt(pStr),
    G: BigInt(gStr),
    y: BigInt(yStr)
  };
}

/**
 * Serialize signature to string format "r,s"
 */
export function serializeSignature(signature: { r: bigint; s: bigint }): string {
  return `${signature.r.toString()},${signature.s.toString()}`;
}

/**
 * Deserialize signature from string format "r,s"
 */
export function deserializeSignature(str: string): { r: bigint; s: bigint } {
  const [rStr, sStr] = str.split(',');
  return {
    r: BigInt(rStr),
    s: BigInt(sStr)
  };
}
