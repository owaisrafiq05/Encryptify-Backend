// SHA-384 implementation in JavaScript
class SHA384 {
    constructor() {
        // Initial hash values for SHA-384 (first 64 bits of square roots of first 8 primes 2..19)
        this.H = [
            0xcbbb9d5dc1059ed8n, 0x629a292a367cd507n,
            0x9159015a3070dd17n, 0x152fecd8f70e5939n,
            0x67332667ffc00b31n, 0x8eb44a8768581511n,
            0xdb0c2e0d64f98fa7n, 0x47b5481dbefa4fa4n
        ];
        
        // Initialize round constants (first 64 bits of cube roots of first 80 primes 2..409)
        this.K = [
            0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn,
            0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 0x59f111f1b605d019n,
            0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n, 0xd807aa98a3030242n,
            0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
            0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n,
            0xc19bf174cf692694n, 0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n,
            0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n, 0x2de92c6f592b0275n,
            0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
            0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn,
            0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n,
            0x06ca6351e003826fn, 0x142929670a0e6e70n, 0x27b70a8546d22ffcn,
            0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
            0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n,
            0x92722c851482353bn, 0xa2bfe8a14cf10364n, 0xa81a664bbc423001n,
            0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n,
            0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
            0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n,
            0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn,
            0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n, 0x748f82ee5defb2fcn,
            0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
            0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n,
            0xc67178f2e372532bn, 0xca273eceea26619cn, 0xd186b8c721c0c207n,
            0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban,
            0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
            0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn,
            0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an,
            0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
        ];
    }

    // Right rotate a 64-bit number n by d bits
    rightRotate(n, d) {
        return (n >> BigInt(d)) | (n << BigInt(64n - BigInt(d)));
    }

    // Process a single 1024-bit block
    processBlock(block) {
        const W = new Array(80).fill(0n);
        
        // Prepare message schedule
        for (let t = 0; t < 16; t++) {
            W[t] = BigInt(`0x${block.slice(t * 16, (t + 1) * 16)}`);
        }

        for (let t = 16; t < 80; t++) {
            const s0 = this.rightRotate(W[t-15], 1) ^ this.rightRotate(W[t-15], 8) ^ (W[t-15] >> 7n);
            const s1 = this.rightRotate(W[t-2], 19) ^ this.rightRotate(W[t-2], 61) ^ (W[t-2] >> 6n);
            W[t] = (W[t-16] + s0 + W[t-7] + s1) & ((1n << 64n) - 1n);
        }

        // Initialize working variables
        let [a, b, c, d, e, f, g, h] = this.H;

        // Main loop
        for (let t = 0; t < 80; t++) {
            const S1 = this.rightRotate(e, 14) ^ this.rightRotate(e, 18) ^ this.rightRotate(e, 41);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + this.K[t] + W[t]) & ((1n << 64n) - 1n);
            const S0 = this.rightRotate(a, 28) ^ this.rightRotate(a, 34) ^ this.rightRotate(a, 39);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) & ((1n << 64n) - 1n);

            h = g;
            g = f;
            f = e;
            e = (d + temp1) & ((1n << 64n) - 1n);
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) & ((1n << 64n) - 1n);
        }

        // Update hash values
        this.H[0] = (this.H[0] + a) & ((1n << 64n) - 1n);
        this.H[1] = (this.H[1] + b) & ((1n << 64n) - 1n);
        this.H[2] = (this.H[2] + c) & ((1n << 64n) - 1n);
        this.H[3] = (this.H[3] + d) & ((1n << 64n) - 1n);
        this.H[4] = (this.H[4] + e) & ((1n << 64n) - 1n);
        this.H[5] = (this.H[5] + f) & ((1n << 64n) - 1n);
        this.H[6] = (this.H[6] + g) & ((1n << 64n) - 1n);
        this.H[7] = (this.H[7] + h) & ((1n << 64n) - 1n);
    }

    // Main hash function
    hash(message) {
        // Convert string to byte array
        const bytes = new TextEncoder().encode(message);
        
        // Prepare blocks
        const padding = new Uint8Array(128 - ((bytes.length + 17) % 128));
        padding[0] = 0x80;
        
        // Append length in bits as big-endian 128-bit integer
        const lengthBits = BigInt(bytes.length * 8);
        const lengthBytes = new Uint8Array(16);
        for (let i = 15; i >= 0; i--) {
            lengthBytes[i] = Number(lengthBits >> BigInt(8 * (15 - i)) & 0xFFn);
        }

        // Combine all parts
        const data = new Uint8Array([...bytes, ...padding, ...lengthBytes]);

        // Process each block
        for (let i = 0; i < data.length; i += 128) {
            const block = Array.from(data.slice(i, i + 128))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            this.processBlock(block);
        }

        // Generate final hash
        return this.H.slice(0, 6)  // SHA-384 uses first 6 of 8 hash values
            .map(h => h.toString(16).padStart(16, '0'))
            .join('');
    }
}

// Usage example:
function encryptThisString(input) {
    const sha384 = new SHA384();
    return sha384.hash(input);
}

// // Example usage:
// console.log("HashCode Generated by SHA-384 for:");
// const s1 = "owais rafiq";
// console.log("\n" + s1 + " : " + encryptThisString(s1));
// const s2 = "hello world";
// console.log("\n" + s2 + " : " + encryptThisString(s2));

export const sha384Hash = async (request, response) => {
    const { text } = request.body;
  
    if (!text) {
      response.json({
        message: "Text is required.",
        status: false,
      });
      return;
    }
  
    try {
      const hash = encryptThisString(text);
      response.json({
        hash,
        message: "Hashing successful.",
        status: true,
      });
    } catch (error) {
      response.json({
        message: "Hashing failed.",
        status: false,
        data: error.message,
      });
    }
  };