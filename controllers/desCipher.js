import BitArray from '../utils/BitArray.js';

let DES = {};

DES.generateRandomKey = function () {
    let result = BitArray.generateRandom(64);
    DES.setParityBits(result);
    return result;
};

DES.generateRandomMessage = function () {
    return BitArray.generateRandom(64);
};

DES.setParityBits = function (bitArray) {
    for (let byteIndex = 0; byteIndex < bitArray.length; byteIndex += 8) {
        let num1Bits = 0;
        
        // Count 1 bits in the first 7 bits of the byte
        for (let bitOffset = 0; bitOffset < 7; bitOffset++) {
            num1Bits += bitArray.get(byteIndex + bitOffset);
        }
        
        // Set the parity bit to make total 1 bits even
        let parityBit = (num1Bits % 2 === 0) ? 0 : 1;
        
        bitArray.set(byteIndex + 7, parityBit);
    }
};

/**
 * Sizes an input to 64 bits exactly. Will add padding with zeros to the end if necessary.
 */
DES._sizeInput = function (input) {
    let result = new BitArray(64);
    let loopTimes = Math.min(result.length, input.length);

    for (let i = 0; i < loopTimes; i++) {
        result.set(i, input.get(i));
    }

    return result;
};

/**
 * Encrypts the given input with the given key. Will return a result containing data from each step of the encryption.
 */
DES.encrypt = function (key, input) {
    // return DES._encryptOrDecrypt(key, input, DES.MODE.ENCRYPTION);
    let sized_key = DES._sizeInput(key);
    let sized_input = DES._sizeInput(input);
    return {
        final: DES._encryptOrDecrypt(sized_key, sized_input, DES.MODE.ENCRYPTION)
    };
};

DES.decrypt = function (key, input) {
    // return DES._encryptOrDecrypt(key, input, DES.MODE.DECRYPTION);
    let sized_key = DES._sizeInput(key);
    let sized_input = DES._sizeInput(input);
    return {
        final: DES._encryptOrDecrypt(sized_key, sized_input, DES.MODE.DECRYPTION)
    };
};

DES._encryptOrDecrypt = function (key, input, mode) {
    // Initial permutation
    let current = DES.permute(input, DES.PERMUTATION_MAPPINGS.INITIAL_PERMUTATION);
    
    // Generate round keys
    let roundKeys = DES._generateKeys(key).roundKeyParts;
    if (mode === DES.MODE.DECRYPTION) {
        roundKeys = roundKeys.slice().reverse();
    }
    
    // Split into left and right halves
    let left = current.slice(0, 32);
    let right = current.slice(32, 64);
    
    // Perform 16 rounds
    for (let round = 0; round < DES.NUM_ROUNDS; round++) {
        let newRight = left.copy();
        let mangledRight = DES._mangle(roundKeys[round], right);
        newRight.xor(mangledRight);
        
        left = right;
        right = newRight;
    }
    
    // Final swap and permutation
    let almostFinal = right.concat(left);  // Note: right and left are swapped
    return DES.permute(almostFinal, DES.PERMUTATION_MAPPINGS.FINAL_PERMUTATION);
};


/**
 * Performs a data permutation. Permutes data according to a permutation mapping, which maps input bit indexes to output bit indexes.
 */
DES.permute = function (data, permutationMapping) {
    let result = new BitArray(permutationMapping.length);

    for (let i = 0; i < permutationMapping.length; i++) {
        result.set(i, data.get(permutationMapping[i] - 1));
    }

    return result;
};

/**
 * Generates per-round keys from an input key. Done in order for encryption; use in reverse for decryption.
 */
DES._generateKeys = function (inputKey) {
    
    let result = {};
    result.roundKeyParts = [];

    // Perform PC1 permutation on the key
    let pc1Key = DES.permute(inputKey, DES.PERMUTATION_MAPPINGS.PC1_C.concat(DES.PERMUTATION_MAPPINGS.PC1_D));
    
    // Split into C and D
    let c = pc1Key.slice(0, 28);
    let d = pc1Key.slice(28, 56);

    for (let round = 0; round < DES.NUM_ROUNDS; round++) {
        // Perform the left shifts
        c = c.copy().shiftLeft(DES.PER_ROUND_KEY_SHIFTS[round], true);
        d = d.copy().shiftLeft(DES.PER_ROUND_KEY_SHIFTS[round], true);

        // Combine C and D
        let combined = c.concat(d);

        // Apply PC2 permutation
        let roundKey = DES.permute(combined, 
            DES.PERMUTATION_MAPPINGS.PC2_C.concat(DES.PERMUTATION_MAPPINGS.PC2_D));

        result.roundKeyParts[round] = roundKey;
    }

    return result;
};

DES._doRounds = function (roundKeys, permutedInput, mode) {
    let result = [];
    let lastRoundOutput = permutedInput;

    for (let roundIndex = 0; roundIndex < DES.NUM_ROUNDS; roundIndex++) {
        let thisRound = {};

        thisRound.input = lastRoundOutput.copy();
        
        // Split input into left and right halves
        thisRound.leftInitial = thisRound.input.slice(0, 32);
        thisRound.rightInitial = thisRound.input.slice(32, 64);

        // For both encryption and decryption:
        // 1. Save the original right half (it will become the next round's left half)
        // 2. Run the mangler function on the right half
        // 3. XOR the mangler output with the left half to get the new right half
        let tempRight = thisRound.rightInitial.copy();
        thisRound.manglerData = DES._mangle(roundKeys[roundIndex].key, thisRound.rightInitial);
        
        thisRound.rightFinal = thisRound.manglerData.finalOutput.copy();
        thisRound.rightFinal.xor(thisRound.leftInitial);
        
        thisRound.leftFinal = tempRight;

        thisRound.finalOutput = thisRound.leftFinal.concat(thisRound.rightFinal);
        
        lastRoundOutput = thisRound.finalOutput;
        
        result[roundIndex] = thisRound;
    }

    return result;
};

DES._mangle = function (roundKey, input) {
      // Expand the 32-bit input to 48 bits
      let expanded = DES.permute(input, DES.PERMUTATION_MAPPINGS.MANGLER_EXPAND_PERMUTATION);
    
      // XOR with round key
      expanded.xor(roundKey);
      
      // Process through S-boxes
      let sboxOutput = new BitArray(32);
      for (let i = 0; i < 8; i++) {
          let chunk = expanded.slice(i * 6, (i + 1) * 6);
          
          // Calculate row and column
          let row = (chunk.get(0) << 1) | chunk.get(5);
          let col = (chunk.get(1) << 3) | (chunk.get(2) << 2) | 
                   (chunk.get(3) << 1) | chunk.get(4);
          
          // Get S-box value
          let value = DES.SBOXES[i][row][col];
          
          // Convert to 4 bits and add to output
          let bits = BitArray.fromNumber(value, 4);
          for (let j = 0; j < 4; j++) {
              sboxOutput.set(i * 4 + j, bits.get(j));
          }
      }
      
      // Final permutation
      return DES.permute(sboxOutput, DES.PERMUTATION_MAPPINGS.SBOX_PERMUTATION);
};

DES._getSBoxInputs = function (expandedData) {
    let result = [];

    for (let i = 0; i < 8; i++) {
        let startBitIndex = i * 6;
        let endBitIndex = startBitIndex + 6;

        result[i] = expandedData.slice(startBitIndex, endBitIndex);
    }

    return result;
};

DES._processSBoxChunks = function (manglerData) {
    manglerData.rowColumnData = [];
    manglerData.sBoxOutputs = [];

    for (let sBoxIndex = 0; sBoxIndex < 8; sBoxIndex++) {
        let rowColumn = DES._getSBoxRowAndColumn(manglerData.sBoxFinalInputs[sBoxIndex]);

        // Log the raw input to the S-Box
        // console.log(`S-Box Final Input for index ${sBoxIndex}:`, manglerData.sBoxFinalInputs[sBoxIndex]);

        // Debug logging for S-Box access
        // console.log(`S-Box Index: ${sBoxIndex}, Row: ${rowColumn.row}, Column: ${rowColumn.column}`);

        // Validate row and column
        if (rowColumn.row < 0 || rowColumn.row > 3 || rowColumn.column < 0 || rowColumn.column > 15) {
            throw new Error(`Invalid row or column: row=${rowColumn.row}, column=${rowColumn.column}`);
        }

        // Get the S-Box value using the validated indices
        const sBoxValue = DES.SBOXES[sBoxIndex][rowColumn.row][rowColumn.column];
        
        // Log the value being accessed from the S-Box
        // console.log(`S-Box Value: ${sBoxValue}`);

        // Ensure the value is non-negative and valid
        if (typeof sBoxValue !== 'number' || sBoxValue < 0 || sBoxValue > 15) {
            throw new Error(`Invalid S-Box value: ${sBoxValue}`);
        }

        manglerData.sBoxOutputs[sBoxIndex] = BitArray.fromNumber(sBoxValue, 4);
        manglerData.rowColumnData[sBoxIndex] = rowColumn;
    }
};
DES._combineSBoxOutputs = function (manglerData) {
    let result = manglerData.sBoxOutputs[0].copy();

    for (let i = 1; i < manglerData.sBoxOutputs.length; i++) {
        result = result.concat(manglerData.sBoxOutputs[i]);
    }

    return result;
};

DES._getSBoxRowAndColumn = function (bitArray) {
    if (bitArray.length !== 6) {
        throw new Error(`Invalid BitArray length: expected 6 but got ${bitArray.length}`);
    }

    // First and last bits form the row number (2 bits)
    const row = (bitArray.get(0) << 1) | bitArray.get(5);
    
    // Middle 4 bits form the column number
    const column = (bitArray.get(1) << 3) | (bitArray.get(2) << 2) | 
                  (bitArray.get(3) << 1) | bitArray.get(4);

    return { row, column };
};
/* Constants */
DES.NUM_ROUNDS = 16;

DES.MODE = {
    ENCRYPTION: 'ENCRYPTION',
    DECRYPTION: 'DECRYPTION',
};

DES.PERMUTATION_MAPPINGS = {
    INITIAL_PERMUTATION: [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7],
    FINAL_PERMUTATION: [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25],
    PC1_C: [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36],
    PC1_D: [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4],
    PC2_C: [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2],
    PC2_D: [41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32],
    MANGLER_EXPAND_PERMUTATION: [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1],
    SBOX_PERMUTATION: [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
};

DES.PER_ROUND_KEY_SHIFTS = [1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2];

const DES_SBOXES = [
    // S-Box 0
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    // S-Box 1
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    // S-Box 2
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 2, 8, 12, 7, 4, 11],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 2, 5, 12]
    ],
    // S-Box 3
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    // S-Box 4
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15 , 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    // S-Box 5
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 14, 1, 7, 6, 11, 0, 8, 13]
    ],
    // S-Box 6
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    // S-Box 7
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
];

// Assign the S-boxes to DES object
DES.SBOXES = DES_SBOXES;


// Fix: Add permutation adjustment function
DES.adjustPermutationIndices = function() {
    for (let key in DES.PERMUTATION_MAPPINGS) {
        DES.PERMUTATION_MAPPINGS[key] = DES.PERMUTATION_MAPPINGS[key].map(x => x-1);
    }
};

// Call the adjustment function once during initialization
DES.adjustPermutationIndices();

// Refactor permute to handle edge cases where indices might be invalid
DES.permute = function (data, permutationMapping) {
    try {
        let result = new BitArray(permutationMapping.length);
        
        for (let i = 0; i < permutationMapping.length; i++) {
            // Adjust the 1-based index to 0-based (already done by the adjustPermutationIndices function)
            const sourceIndex = permutationMapping[i];
            if (sourceIndex < 0 || sourceIndex >= data.length) {
                throw new Error(`Invalid permutation index: ${sourceIndex} for data length: ${data.length}`);
            }
            result.set(i, data.get(sourceIndex));
        }
        
        return result;
    } catch (error) {
        throw new Error(`Permutation error: ${error.message}`);
    }
};


function textToHex(text) {
    // Ensure exactly 16 hex characters (64 bits)
    const hex = text.split('').map(char => 
        char.charCodeAt(0).toString(16).padStart(2, '0')
    ).join('').toUpperCase();
    
    return hex.padEnd(16, '0').slice(0, 16);
}

export const desEncrypt = async (req, res) => {
    try {
        const { message, key } = req.body;

        // Convert text to hex if not already hex
        const hexMessage = /^[0-9A-Fa-f]{16}$/.test(message) 
            ? message 
            : textToHex(message);
        
        const hexKey = /^[0-9A-Fa-f]{16}$/.test(key) 
            ? key 
            : textToHex(key);

        try {
            const keyBitArray = BitArray.fromHexString(hexKey);
            const messageBitArray = BitArray.fromHexString(hexMessage);
            
            const result = DES.encrypt(keyBitArray, messageBitArray);
            const hexResult = result.final.toHexString();
            
            return res.status(200).json({
                success: true,
                originalMessage: message,
                originalKey: key,
                hexMessage: hexMessage,
                hexKey: hexKey,
                encryptedData: hexResult,
                message: "Message encrypted successfully"
            });
        } catch (error) {
            console.error('Encryption processing error:', error);
            return res.status(500).json({
                success: false,
                message: "Failed to process encryption: " + error.message
            });
        }
    } catch (error) {
        console.error('Unhandled error in desEncrypt:', error);
        return res.status(500).json({
            success: false,
            message: "Internal server error during encryption"
        });
    }
};

export const desDecrypt = async (req, res) => {
    try {
        const { message, key } = req.body;

        // Convert text to hex if not already hex
        const hexMessage = /^[0-9A-Fa-f]{16}$/.test(message) 
            ? message 
            : textToHex(message);
        
        const hexKey = /^[0-9A-Fa-f]{16}$/.test(key) 
            ? key 
            : textToHex(key);

        try {
            const keyBitArray = BitArray.fromHexString(hexKey);
            const ciphertextBitArray = BitArray.fromHexString(hexMessage);
            
            const result = DES.decrypt(keyBitArray, ciphertextBitArray);
            const hexResult = result.final.toHexString();
            
            return res.status(200).json({
                success: true,
                originalCiphertext: message,
                originalKey: key,
                hexCiphertext: hexMessage,
                hexKey: hexKey,
                decryptedData: hexResult,
                message: "Message decrypted successfully"
            });
        } catch (error) {
            console.error('Decryption processing error:', error);
            return res.status(500).json({
                success: false,
                message: "Failed to process decryption: " + error.message
            });
        }
    } catch (error) {
        console.error('Unhandled error in desDecrypt:', error);
        return res.status(500).json({
            success: false,
            message: "Internal server error during decryption"
        });
    }
};