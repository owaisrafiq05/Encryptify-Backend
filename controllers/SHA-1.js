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

// Corrected SHA-1 Hash Function
const sha1 = (message) => {
    // Convert to UTF-8 bytes
    const utf8 = new TextEncoder().encode(message);

    // Initial hash values (standard SHA-1 initialization)
    let h0 = 0x67452301;
    let h1 = 0xEFCDAB89;
    let h2 = 0x98BADCFE;
    let h3 = 0x10325476;
    let h4 = 0xC3D2E1F0;

    // Preprocessing: Padding
    const originalLength = utf8.length * 8;
    const blockCount = Math.ceil((originalLength + 65) / 512);
    const paddedLength = blockCount * 64;
    const padded = new Uint8Array(paddedLength);

    // Copy original message
    padded.set(utf8);

    // Append 1 bit
    padded[utf8.length] = 0x80;

    // Append length in big-endian
    const lengthView = new DataView(padded.buffer);
    lengthView.setBigUint64(paddedLength - 8, BigInt(originalLength), false);

    // Process each 64-byte block
    for (let offset = 0; offset < padded.length; offset += 64) {
        const block = padded.slice(offset, offset + 64);
        const w = new Array(80).fill(0);

        // First 16 words from the block
        for (let i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) 
                 | (block[i * 4 + 1] << 16) 
                 | (block[i * 4 + 2] << 8) 
                 | block[i * 4 + 3];
        }

        // Extend to 80 words
        for (let i = 16; i < 80; i++) {
            w[i] = leftRotate(
                w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 
                1
            );
        }

        // Initial variables
        let a = h0;
        let b = h1;
        let c = h2;
        let d = h3;
        let e = h4;

        // Main loop
        for (let i = 0; i < 80; i++) {
            let f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            const temp = (leftRotate(a, 5) + f + e + w[i] + k) >>> 0;
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        // Update hash values
        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }

    // Convert to hex string
    return [h0, h1, h2, h3, h4]
        .map(h => h.toString(16).padStart(8, '0'))
        .join('');
};

// Left rotate function
const leftRotate = (x, n) => {
    return ((x << n) | (x >>> (32 - n))) >>> 0;
};

export default sha1Hash;