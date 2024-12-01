// SHA-1 Cipher Function
export const sha1Hash = (req, res) => {
    const { text } = req.body;

    if (!text) {
        return res.status(400).json({
            message: "Text is required for hashing.",
            status: false,
        });
    }

    try {
        const hash = sha1(text);
        res.status(200).json({
            message: "SHA-1 Hashing successful",
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

// SHA-1 Hash Function (Pure JavaScript)
const sha1 = (text) => {
    const message = encodeMessage(text);
    const paddedMessage = padMessage(message);
    const hash = processBlocks(paddedMessage);
    return hashToHex(hash);
};

// Message Encoding (Convert to an array of bytes)
const encodeMessage = (text) => {
    const encoder = new TextEncoder();
    return encoder.encode(text); // Returns a Uint8Array
};

// Padding the message to make it a multiple of 512 bits (64 bytes)
const padMessage = (message) => {
    const originalLength = message.length * 8; // length in bits
    const paddingLength = (448 - originalLength % 512 + 512) % 512; // How many bits to pad
    const totalLength = message.length + Math.floor(paddingLength / 8) + 8; // Total length in bytes
    const padding = new Uint8Array(totalLength);

    // Copy the original message into the padded array
    padding.set(message);

    // Append the '1' bit (0x80) followed by the zeros
    padding[message.length] = 0x80;

    // Append the original length (in bits) as a 64-bit big-endian integer
    const lengthPos = totalLength - 8;
    for (let i = 0; i < 8; i++) {
        padding[lengthPos + i] = (originalLength >>> (56 - i * 8)) & 0xFF;
    }

    return padding;
};

// Process the padded message in 512-bit blocks
const processBlocks = (blocks) => {
    let h0 = 0x67452301;
    let h1 = 0xEFCDAB89;
    let h2 = 0x98BADCFE;
    let h3 = 0x10325476;
    let h4 = 0xC3D2E1F0;

    for (let i = 0; i < blocks.length; i += 64) {
        const block = blocks.slice(i, i + 64);
        const w = new Array(80);

        // Prepare the message schedule (first 16 words)
        for (let t = 0; t < 16; t++) {
            w[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | block[t * 4 + 3];
        }

        // Extend the message schedule to 80 words
        for (let t = 16; t < 80; t++) {
            w[t] = leftRotate(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }

        // Initialize the working variables
        let a = h0;
        let b = h1;
        let c = h2;
        let d = h3;
        let e = h4;

        // Main loop: Perform the 80 rounds
        for (let t = 0; t < 80; t++) {
            let f, k;
            if (t < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            const temp = (leftRotate(a, 5) + f + e + w[t] + k) & 0xFFFFFFFF;
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        // Add the compressed chunk to the current hash values
        h0 = (h0 + a) & 0xFFFFFFFF;
        h1 = (h1 + b) & 0xFFFFFFFF;
        h2 = (h2 + c) & 0xFFFFFFFF;
        h3 = (h3 + d) & 0xFFFFFFFF;
        h4 = (h4 + e) & 0xFFFFFFFF;
    }

    // Return the final hash values
    return [h0, h1, h2, h3, h4];
};

// Left rotate function
const leftRotate = (n, bits) => {
    return (n << bits) | (n >>> (32 - bits));
};

// Convert the hash to a hexadecimal string
const hashToHex = (hash) => {
    return hash.map(num => num.toString(16).padStart(8, '0')).join('');
};

export default sha1Hash;
