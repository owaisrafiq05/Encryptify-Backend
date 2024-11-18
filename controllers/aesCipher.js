// AES Encryption & Decryption without external libraries

// Encrypt endpoint
export const aesEncrypt = (req, res) => {
  const { text, key } = req.body;

  if (!text || !key) {
    return res.status(400).json({
      message: "Text and key are required for encryption.",
      status: false,
    });
  }

  if (key.length !== 16) {
    return res.status(400).json({
      message: "Key length should be 16 characters (128 bits).",
      status: false,
    });
  }

  try {
    const iv = generateRandomBytes(16);
    const encryptedText = aesCbcEncrypt(text, key, iv);

    res.status(200).json({
      message: "Encryption successful",
      encryptedText: iv + encryptedText,
      status: true,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
      status: false,
    });
  }
};

// Decrypt endpoint
export const aesDecrypt = (req, res) => {
  const { text, key } = req.body;

  if (!text || !key) {
    return res.status(400).json({
      message: "Text and key are required for decryption.",
      status: false,
    });
  }

  if (key.length !== 16) {
    return res.status(400).json({
      message: "Key length should be 16 characters (128 bits).",
      status: false,
    });
  }

  try {
    const iv = text.slice(0, 16); // Extract the IV from the beginning
    const encryptedText = text.slice(16);
    const decryptedText = aesCbcDecrypt(encryptedText, key, iv);

    res.status(200).json({
      message: "Decryption successful",
      decryptedText: decryptedText,
      status: true,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
      status: false,
    });
  }
};

// Helper function to convert a string to an array of byte values
const stringToBytes = (str) => Array.from(str).map(c => c.charCodeAt(0));

// Helper function to convert an array of byte values to a string
const bytesToString = (bytes) => bytes.map(b => String.fromCharCode(b)).join('');

// Generate Random Bytes
const generateRandomBytes = (length) => {
  let bytes = "";
  for (let i = 0; i < length; i++) {
    bytes += String.fromCharCode(Math.floor(Math.random() * 256));
  }
  return bytes;
};

// AES CBC Encryption
const aesCbcEncrypt = (text, key, iv) => {
  const paddedText = pkcs7Pad(text, 16);
  const blocks = [];
  let previousBlock = stringToBytes(iv);  // Convert IV to bytes

  for (let i = 0; i < paddedText.length; i += 16) {
    let block = stringToBytes(paddedText.slice(i, i + 16));

    // XOR with previous block (IV for the first block)
    block = xorBlocks(block, previousBlock);

    // Encrypt the block
    const encryptedBlock = aesEncryptBlock(block, keyExpansion(key));
    blocks.push(bytesToString(encryptedBlock));  // Convert back to string

    previousBlock = encryptedBlock;
  }

  return blocks.join("");
};

// AES CBC Decryption
const aesCbcDecrypt = (encryptedText, key, iv) => {
  const blocks = [];
  let previousBlock = stringToBytes(iv);
  const expandedKey = keyExpansion(key);

  for (let i = 0; i < encryptedText.length; i += 16) {
    let block = stringToBytes(encryptedText.slice(i, i + 16));

    // Decrypt the block
    const decryptedBlock = aesDecryptBlock(block, expandedKey);

    // XOR with previous block (IV for the first block)
    const originalBlock = xorBlocks(decryptedBlock, previousBlock);
    blocks.push(bytesToString(originalBlock));  // Convert back to string

    previousBlock = block;
  }

  return pkcs7Unpad(blocks.join(""));
};

// XOR two blocks
const xorBlocks = (block1, block2) => {
  return block1.map((byte, i) => byte ^ block2[i]);
};

// PKCS7 Padding
const pkcs7Pad = (text, blockSize) => {
  const padSize = blockSize - (text.length % blockSize);
  const padding = String.fromCharCode(padSize).repeat(padSize);
  return text + padding;
};

// PKCS7 Unpadding
const pkcs7Unpad = (text) => {
  const padSize = text.charCodeAt(text.length - 1);
  return text.slice(0, -padSize);
};

// AES Encrypt single block
const aesEncryptBlock = (block, expandedKey) => {
  addRoundKey(block, expandedKey.slice(0, 16));
  for (let round = 1; round < 10; round++) {
    subBytes(block);
    shiftRows(block);
    mixColumns(block);
    addRoundKey(block, expandedKey.slice(round * 16, (round + 1) * 16));
  }
  subBytes(block);
  shiftRows(block);
  addRoundKey(block, expandedKey.slice(160, 176));
  return block;
};

// AES Decrypt single block
const aesDecryptBlock = (block, expandedKey) => {
  addRoundKey(block, expandedKey.slice(160, 176));
  invShiftRows(block);
  invSubBytes(block);
  for (let round = 9; round > 0; round--) {
    addRoundKey(block, expandedKey.slice(round * 16, (round + 1) * 16));
    invMixColumns(block);
    invShiftRows(block);
    invSubBytes(block);
  }
  addRoundKey(block, expandedKey.slice(0, 16));
  return block;
};

// AddRoundKey Transformation
const addRoundKey = (state, roundKey) => {
  for (let i = 0; i < 16; i++) {
    state[i] ^= roundKey[i];
  }
};

// SubBytes Transformation
const subBytes = (state) => {
  for (let i = 0; i < state.length; i++) {
    state[i] = sBox[state[i]];
  }
};

// Inverse SubBytes Transformation
const invSubBytes = (state) => {
  for (let i = 0; i < state.length; i++) {
    state[i] = invSBox[state[i]];
  }
};

// ShiftRows Transformation
const shiftRows = (state) => {
  const temp = state.slice();
  state[1] = temp[5];
  state[5] = temp[9];
  state[9] = temp[13];
  state[13] = temp[1];
  state[2] = temp[10];
  state[10] = temp[14];
  state[14] = temp[6];
  state[6] = temp[2];
  state[3] = temp[15];
  state[15] = temp[11];
  state[11] = temp[7];
  state[7] = temp[3];
};

// Inverse ShiftRows Transformation
const invShiftRows = (state) => {
  const temp = state.slice();
  state[1] = temp[13];
  state[5] = temp[1];
  state[9] = temp[5];
  state[13] = temp[9];
  state[2] = temp[6];
  state[6] = temp[10];
  state[10] = temp[14];
  state[14] = temp[2];
  state[3] = temp[7];
  state[7] = temp[11];
  state[11] = temp[15];
  state[15] = temp[3];
};

// MixColumns Transformation
const mixColumns = (state) => {
  for (let i = 0; i < 4; i++) {
    const a = state[i * 4];
    const b = state[i * 4 + 1];
    const c = state[i * 4 + 2];
    const d = state[i * 4 + 3];

    state[i * 4] = (a * 2) ^ (b * 3) ^ c ^ d;
    state[i * 4 + 1] = a ^ (b * 2) ^ (c * 3) ^ d;
    state[i * 4 + 2] = a ^ b ^ (c * 2) ^ (d * 3);
    state[i * 4 + 3] = (a * 3) ^ b ^ c ^ (d * 2);
  }
};

// Inverse MixColumns Transformation
const invMixColumns = (state) => {
  for (let i = 0; i < 4; i++) {
    const a = state[i * 4];
    const b = state[i * 4 + 1];
    const c = state[i * 4 + 2];
    const d = state[i * 4 + 3];

    state[i * 4] = (a * 14) ^ (b * 11) ^ (c * 13) ^ (d * 9);
    state[i * 4 + 1] = (a * 9) ^ (b * 14) ^ (c * 11) ^ (d * 13);
    state[i * 4 + 2] = (a * 13) ^ (b * 9) ^ (c * 14) ^ (d * 11);
    state[i * 4 + 3] = (a * 11) ^ (b * 13) ^ (c * 9) ^ (d * 14);
  }
};

// AES Key Expansion
const keyExpansion = (key) => {
  const expandedKey = new Uint8Array(176);
  for (let i = 0; i < key.length; i++) {
    expandedKey[i] = key.charCodeAt(i);
  }

  let bytesGenerated = key.length;
  let rconIndex = 1;
  const temp = new Uint8Array(4);

  while (bytesGenerated < 176) {
    for (let i = 0; i < 4; i++) {
      temp[i] = expandedKey[bytesGenerated - 4 + i];
    }

    if (bytesGenerated % 16 === 0) {
      keyScheduleCore(temp, rconIndex++);
    }

    for (let i = 0; i < 4; i++) {
      expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 16] ^ temp[i];
      bytesGenerated++;
    }
  }

  return expandedKey;
};

// Key Schedule Core
const keyScheduleCore = (word, rconIndex) => {
  const temp = word[0];
  for (let i = 0; i < 3; i++) {
    word[i] = word[i + 1];
  }
  word[3] = temp;

  for (let i = 0; i < 4; i++) {
    word[i] = sBox[word[i]];
  }

  word[0] ^= rcon[rconIndex];
};

// S-box array
const sBox = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
  0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
  0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
  0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
  0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
  0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
  0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
  0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
  0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
  0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
  0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
  0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
  0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
  0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
  0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// Inverse S-box array
const invSBox = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81,
  0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
  0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23,
  0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
  0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72,
  0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
  0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46,
  0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca,
  0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
  0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
  0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
  0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f,
  0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
  0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
  0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93,
  0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
  0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
  0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// RCON array
const rcon = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
  0x7d, 0xfa, 0xef, 0xc5, 0x91
];
