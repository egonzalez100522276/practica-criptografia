/**
 * PKI Module for Client-Side CA Signature Verification
 * 
 * Provides functions to verify that public keys are properly signed by the CA.
 */

import * as forge from 'node-forge';

let cachedCAPublicKey: forge.pki.rsa.PublicKey | null = null;

/**
 * Fetch the CA public key from the backend
 */
export async function getCAPublicKey(): Promise<forge.pki.rsa.PublicKey> {
  if (cachedCAPublicKey) {
    return cachedCAPublicKey;
  }

  try {
    const response = await fetch('http://127.0.0.1:8000/pki/ca-public-key');
    if (!response.ok) {
      throw new Error('Failed to fetch CA public key');
    }

    const { public_key_pem } = await response.json();
    cachedCAPublicKey = forge.pki.publicKeyFromPem(public_key_pem);
    return cachedCAPublicKey;
  } catch (error) {
    console.error('Error fetching CA public key:', error);
    throw new Error('Could not retrieve CA public key for verification');
  }
}

/**
 * Verify a CA signature on data
 * 
 * @param data - The data that was signed (e.g., public key PEM)
 * @param signatureBase64 - The signature in base64 format
 * @returns true if signature is valid, false otherwise
 */
export async function verifyCASignature(data: string, signatureBase64: string): Promise<boolean> {
  try {
    const caPublicKey = await getCAPublicKey();
    
    // Decode the signature from base64
    const signatureBytes = forge.util.decode64(signatureBase64);
    
    // Create a message digest
    const md = forge.md.sha256.create();
    md.update(data, 'utf8');
    
    // Verify the signature using PSS padding (same as backend)
    const pss = forge.pss.create({
      md: forge.md.sha256.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
      saltLength: 32 // Maximum salt length for SHA-256
    });
    
    return caPublicKey.verify(md.digest().bytes(), signatureBytes, pss);
  } catch (error) {
    console.error('Error verifying CA signature:', error);
    return false;
  }
}

/**
 * Verify that a user's public key has a valid CA signature
 * 
 * @param publicKeyPem - The user's RSA public key in PEM format
 * @param signatureBase64 - The CA signature in base64 format
 * @returns true if the key is properly signed by the CA
 */
export async function verifyUserPublicKey(publicKeyPem: string, signatureBase64: string | null): Promise<boolean> {
  if (!signatureBase64) {
    console.warn('Public key has no CA signature');
    return false;
  }

  return await verifyCASignature(publicKeyPem, signatureBase64);
}

/**
 * Verify that a user's ElGamal public key has a valid CA signature
 * 
 * @param elgamalPublicKeyJson - The ElGamal public key as JSON string
 * @param signatureBase64 - The CA signature in base64 format
 * @returns true if the key is properly signed by the CA
 */
export async function verifyElGamalPublicKey(elgamalPublicKeyJson: string, signatureBase64: string | null): Promise<boolean> {
  if (!signatureBase64) {
    console.warn('ElGamal public key has no CA signature');
    return false;
  }

  return await verifyCASignature(elgamalPublicKeyJson, signatureBase64);
}
