// Function to handle the SHA-512 hashing request and return the result
export const sha512Hash = (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).json({
      message: "Text is required for hashing.",
      status: false,
    });
  }
  try {
    const hash = sha512(text); // Call the sha512 function to compute the hash
    res.status(200).json({
      message: "Hashing successful",
      hash: hash,
      status: true,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
      status: false,
    });
  }
};

// Constants for SHA-512: These are the constants used in the SHA-512 algorithm, including K (round constants) and H (initial hash values).
const K = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
  0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
  0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
  0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
  0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];

// Initial hash values for SHA-512
const H = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

// Utility function to rotate a 64-bit number to the right by n positions
const rotateRight = (x, n) => (x >> n) | (x << (64n - n));

// Padding function to ensure the message length is a multiple of 1024 bits (128 bytes)
const padMessage = (message) => {
  const bytes = new TextEncoder().encode(message); // Convert message to bytes
  const bitLength = BigInt(bytes.length * 8); // Calculate the bit length of the message
  const padding = Buffer.alloc((bytes.length + 17) % 128 === 0 ? 0 : 128 - ((bytes.length + 17) % 128)); // Calculate padding size
  padding[0] = 0x80; // Set the first byte of padding to 0x80 (indicating the end of the message)
  const lengthBuffer = Buffer.alloc(16); // Buffer to store the length of the message
  lengthBuffer.writeBigUInt64BE(bitLength, 8); // Write the length of the message in big-endian format
  return Buffer.concat([Buffer.from(bytes), padding, lengthBuffer]); // Concatenate the message, padding, and length
};

// Main SHA-512 function to compute the hash of a given message
function sha512(message) {
  const paddedMessage = padMessage(message); // Pad the message to the correct length
  const blocks = paddedMessage.length / 128; // Calculate the number of 128-byte blocks

  let [a, b, c, d, e, f, g, h] = H; // Initialize the hash values

  for (let i = 0; i < blocks; i++) {
    const W = Array(80).fill(0n); // Initialize the message schedule array
    const block = paddedMessage.slice(i * 128, (i + 1) * 128); // Get the current 128-byte block

    // Message schedule: Fill the first 16 values of W with the current block
    for (let t = 0; t < 16; t++) {
      W[t] = BigInt('0x' + block.slice(t * 8, t * 8 + 8).toString('hex'));
    }
    // Extend the message schedule to 80 words
    for (let t = 16; t < 80; t++) {
      const s0 = rotateRight(W[t - 15], 1n) ^ rotateRight(W[t - 15], 8n) ^ (W[t - 15] >> 7n);
      const s1 = rotateRight(W[t - 2], 19n) ^ rotateRight(W[t - 2], 61n) ^ (W[t - 2] >> 6n);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & (2n ** 64n - 1n); // Update W[t] using the SHA-512 transformation
    }

    // Compression function: Perform the main computation steps
    let [A, B, C, D, E, F, G, H] = [a, b, c, d, e, f, g, h];
    for (let t = 0; t < 80; t++) {
      const S1 = rotateRight(E, 14n) ^ rotateRight(E, 18n) ^ rotateRight(E, 41n);
      const ch = (E & F) ^ (~E & G);
      const temp1 = (H + S1 + ch + K[t] + W[t]) & (2n ** 64n - 1n); // Calculate temp1
      const S0 = rotateRight(A, 28n) ^ rotateRight(A, 34n) ^ rotateRight(A, 39n);
      const maj = (A & B) ^ (A & C) ^ (B & C);
      const temp2 = (S0 + maj) & (2n ** 64n - 1n); // Calculate temp2

      // Update the hash values
      [H, G, F, E, D, C, B, A] = [G, F, E, (D + temp1) & (2n ** 64n - 1n), C, B, A, (temp1 + temp2) & (2n ** 64n - 1n)];
    }

    // Add the compressed values to the current hash values
    a = (a + A) & (2n ** 64n - 1n);
    b = (b + B) & (2n ** 64n - 1n);
    c = (c + C) & (2n ** 64n - 1n);
    d = (d + D) & (2n ** 64n - 1n);
    e = (e + E) & (2n ** 64n - 1n);
    f = (f + F) & (2n ** 64n - 1n);
    g = (g + G) & (2n ** 64n - 1n);
    h = (h + H) & (2n ** 64n - 1n);
  }

  // Combine the final hash values into one big integer
  const hash = [a, b, c, d, e, f, g, h].map((val) => val.toString(16).padStart(16, '0')).join('');
  return hash; // Return the final hash as a hexadecimal string
}
