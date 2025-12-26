// Vulnerable Diffie-Hellman Key Exchange (NO SIGNATURES)
// This demonstrates why signatures are necessary

const crypto = require('crypto');

class VulnerableDHKeyExchange {
  constructor() {
    // Standard DH parameters (MODP group 14)
    this.prime = Buffer.from(
      'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
      'hex'
    );
    this.generator = 2;
    this.privateKey = null;
    this.publicKey = null;
    this.sharedSecret = null;
  }

  // Generate private and public keys
  generateKeys() {
    // Generate random private key (256 bits)
    this.privateKey = crypto.randomBytes(32);
    
    // Calculate public key: g^privateKey mod p
    const privateBN = BigInt('0x' + this.privateKey.toString('hex'));
    const generatorBN = BigInt(this.generator);
    const primeBN = BigInt('0x' + this.prime.toString('hex'));
    
    const publicBN = this.modPow(generatorBN, privateBN, primeBN);
    this.publicKey = Buffer.from(publicBN.toString(16).padStart(512, '0'), 'hex');
    
    return this.publicKey;
  }

  // Compute shared secret from other party's public key
  computeSharedSecret(otherPublicKey) {
    const otherPublicBN = BigInt('0x' + otherPublicKey.toString('hex'));
    const privateBN = BigInt('0x' + this.privateKey.toString('hex'));
    const primeBN = BigInt('0x' + this.prime.toString('hex'));
    
    const sharedBN = this.modPow(otherPublicBN, privateBN, primeBN);
    this.sharedSecret = Buffer.from(sharedBN.toString(16).padStart(512, '0'), 'hex');
    
    return this.sharedSecret;
  }

  // Derive session key from shared secret
  deriveSessionKey() {
    if (!this.sharedSecret) {
      throw new Error('Shared secret not computed yet');
    }
    
    return crypto.createHash('sha256').update(this.sharedSecret).digest();
  }

  // Modular exponentiation helper
  modPow(base, exponent, modulus) {
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exponent = exponent >> 1n;
      base = (base * base) % modulus;
    }
    
    return result;
  }
}

module.exports = VulnerableDHKeyExchange;