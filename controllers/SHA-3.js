// SHA-3 Cipher Function (SHA3-256)
export const sha3Hash = (req, res) => {
    const { text } = req.body;

    if (!text) {
        return res.status(400).json({
            message: "Text is required for hashing.",
            status: false,
        });
    }

    try {
        const hash = sha3(text);
        res.status(200).json({
            message: "SHA-3 (SHA3-256) Hashing successful",
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

// SHA-3 Hash Function (SHA3-256)
const sha3 = (message) => {
    // Convert message to UTF-8 bytes
    const utf8 = new TextEncoder().encode(message);
    const messageLength = utf8.length * 8;

    // Padding the message according to SHA-3 specification
    const paddedMessage = padMessage(utf8, messageLength);
    const state = new Array(25).fill(0);  // Initialize the state (array of 25 64-bit words)

    // Process each block of the padded message
    for (let blockStart = 0; blockStart < paddedMessage.length; blockStart += SHA3_RATE) {
        let block = new Array(SHA3_RATE);
        for (let i = 0; i < SHA3_RATE; i++) {
            block[i] = paddedMessage[blockStart + i];
        }

        // XOR the input block into the state
        for (let i = 0; i < SHA3_RATE; i++) {
            state[i] ^= block[i];
        }

        // Perform the SHA3 rounds
        keccakF1600(state);
    }

    // Extract the result from the state (SHA3-256 produces 32-byte hash)
    return toHexString(state.slice(0, 32));  // Return the first 32 bytes for SHA3-256
};

// Keccak-f permutation function (core of SHA-3)
const keccakF1600 = (state) => {
    const roundConstants = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000000, 0x8000000000008008
    ];

    let stateCopy = [...state];

    for (let round = 0; round < SHA3_ROUNDS; round++) {
        // Theta step
        const C = new Array(5).fill(0);
        for (let x = 0; x < 5; x++) {
            C[x] = stateCopy[x] ^ stateCopy[x + 5] ^ stateCopy[x + 10] ^ 
                stateCopy[x + 15] ^ stateCopy[x + 20];
        }
        for (let x = 0; x < 5; x++) {
            const temp = C[(x + 4) % 5] ^ (C[(x + 1) % 5] << 1) ^ (C[(x + 2) % 5] >>> 1);
            for (let y = 0; y < 25; y += 5) {
                stateCopy[x + y] ^= temp;
            }
        }

        // Rho step (rotation)
        let current = 1;
        let prev = stateCopy[0];
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) {
                const index = x + y * 5;
                const temp = stateCopy[index];
                stateCopy[index] = (prev << current) | (prev >>> (64 - current));
                prev = temp;
                current = (current + 1) % 64;
            }
        }

        // Pi step (permutation)
        let tempState = [...stateCopy];
        for (let i = 0; i < 25; i++) {
            const x = (i % 5 + 3 * i % 5) % 5;
            const y = i * 2 % 5;
            stateCopy[x + y * 5] = tempState[i];
        }

        // Chi step (non-linear transformation)
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                const index = x + y * 5;
                const temp = stateCopy[index];
                stateCopy[index] = temp ^ ((stateCopy[(x + 1) % 5 + y * 5] ^ 0xFFFFFFFF) & stateCopy[(x + 2) % 5 + y * 5]);
            }
        }

        // Iota step (round constants)
        stateCopy[0] ^= roundConstants[round];
    }

    return stateCopy;
};

// Padding function for SHA-3
const padMessage = (message, messageLength) => {
    const paddingLength = SHA3_BLOCK_SIZE - (messageLength % SHA3_BLOCK_SIZE);
    const paddedMessage = new Uint8Array(message.length + paddingLength);
    paddedMessage.set(message);
    paddedMessage[message.length] = 0x01;
    paddedMessage[paddedMessage.length - 1] = 0x80; // padding ends with 1 byte of 0x80
    return paddedMessage;
};

// Convert an array of bytes to a hexadecimal string
const toHexString = (byteArray) => {
    return byteArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
};

// Constants for SHA-3 (SHA3-256)
const SHA3_ROUNDS = 24;
const SHA3_BLOCK_SIZE = 200;  // SHA3-256 uses 200 bytes block size
const SHA3_RATE = 136;        // SHA3-256 uses 136 bytes rate

export default sha3Hash;
