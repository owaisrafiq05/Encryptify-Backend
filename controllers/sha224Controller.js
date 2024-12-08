export const sha224Hash = (req, res) => {
    // This function handles the incoming request to hash a text message using SHA-224.
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({
        message: "Text is required for hashing.",
        status: false,
      });
    }
    try {
      // Hash the message using the sha224 function
      const hash = sha224(text);
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

function sha224(message) {
    // This function performs SHA-224 hashing on the provided message.

    // Initial hash values for SHA-224
    const H = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ];

    // K constants used in the SHA-224 algorithm for each round of the hash function
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    // Helper function for rotating bits right
    function ROTR(n, x) {
        return (x >>> n) | (x << (32 - n));
    }

    // Helper function for the "Ch" operation in SHA-224
    function Ch(x, y, z) {
        return (x & y) ^ (~x & z);
    }

    // Helper function for the "Maj" operation in SHA-224
    function Maj(x, y, z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    // Helper function for the Σ0 operation in SHA-224
    function Σ0(x) {
        return ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x);
    }

    // Helper function for the Σ1 operation in SHA-224
    function Σ1(x) {
        return ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x);
    }

    // Helper function for the σ0 operation in SHA-224
    function σ0(x) {
        return ROTR(7, x) ^ ROTR(18, x) ^ (x >>> 3);
    }

    // Helper function for the σ1 operation in SHA-224
    function σ1(x) {
        return ROTR(17, x) ^ ROTR(19, x) ^ (x >>> 10);
    }

    // Pre-processing the input message (convert to bytes and add padding)
    const messageBytes = new TextEncoder().encode(message);
    const bitLength = messageBytes.length * 8;

    // Padding the message to ensure its length is a multiple of 512 bits
    const paddedMessage = new Uint8Array(
        ((messageBytes.length + 9 + 63) & ~63) // Round to nearest multiple of 64 bytes
    );
    paddedMessage.set(messageBytes);
    paddedMessage[messageBytes.length] = 0x80; // Append '1' bit
    new DataView(paddedMessage.buffer).setUint32(paddedMessage.length - 4, bitLength, false); // Append length

    // Process the message in 512-bit chunks
    for (let i = 0; i < paddedMessage.length; i += 64) {
        const chunk = new DataView(paddedMessage.buffer, i, 64);

        // Prepare message schedule
        const W = new Uint32Array(64);
        for (let t = 0; t < 16; t++) {
            W[t] = chunk.getUint32(t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
            W[t] = (σ1(W[t - 2]) + W[t - 7] + σ0(W[t - 15]) + W[t - 16]) >>> 0;
        }

        // Initialize working variables
        let [a, b, c, d, e, f, g, h] = H;

        // Main loop to calculate the hash
        for (let t = 0; t < 64; t++) {
            const T1 = (h + Σ1(e) + Ch(e, f, g) + K[t] + W[t]) >>> 0;
            const T2 = (Σ0(a) + Maj(a, b, c)) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + T1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) >>> 0;
        }

        // Update hash values
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }

    // Produce the final hash (truncated to 224 bits)
    return H.slice(0, 7)
        .map(h => h.toString(16).padStart(8, "0"))
        .join("");
}

export default sha224;
