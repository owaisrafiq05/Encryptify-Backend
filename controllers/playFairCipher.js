// Playfair Cipher Encryption and Decryption Controller

export const playfairEncrypt = (req, res) => {
    const { text, key } = req.body;

    if (!text || !key) {
        return res.status(400).json({
            message: "Text and key are required for encryption.",
            status: false
        });
    }

    try {
        const encryptedText = playfairCipher(text, key, "encrypt");
        res.status(200).json({
            message: "Encryption successful",
            encryptedText: encryptedText,
            status: true
        });
    } catch (error) {
        res.status(500).json({
            message: error.message,
            status: false
        });
    }
};

export const playfairDecrypt = (req, res) => {
    const { text, key } = req.body;

    if (!text || !key) {
        return res.status(400).json({
            message: "Text and key are required for decryption.",
            status: false
        });
    }

    try {
        const decryptedText = playfairCipher(text, key, "decrypt");
        res.status(200).json({
            message: "Decryption successful",
            decryptedText: decryptedText,
            status: true
        });
    } catch (error) {
        res.status(500).json({
            message: error.message,
            status: false
        });
    }
};

// Helper functions for Playfair cipher
const generatePlayfairMatrix = (key) => {
    // Remove spaces and convert to uppercase
    key = key.replace(/\s/g, '').toUpperCase();
    // Replace J with I
    key = key.replace(/J/g, 'I');
    
    // Create array of unique characters from key
    const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
    const matrix = [];
    const used = new Set();

    // Add key characters first
    for (let char of key) {
        if (!used.has(char) && char.match(/[A-Z]/)) {
            matrix.push(char);
            used.add(char);
        }
    }

    // Add remaining alphabet
    for (let char of alphabet) {
        if (!used.has(char)) {
            matrix.push(char);
            used.add(char);
        }
    }

    // Convert to 5x5 matrix
    const playfairMatrix = [];
    for (let i = 0; i < 5; i++) {
        playfairMatrix.push(matrix.slice(i * 5, (i + 1) * 5));
    }

    return playfairMatrix;
};

const findPosition = (matrix, char) => {
    for (let i = 0; i < 5; i++) {
        for (let j = 0; j < 5; j++) {
            if (matrix[i][j] === char) {
                return [i, j];
            }
        }
    }
    return null;
};

const prepareText = (text) => {
    // Remove spaces and convert to uppercase
    text = text.replace(/\s/g, '').toUpperCase();
    // Replace J with I
    text = text.replace(/J/g, 'I');
    
    // Split text into pairs and add X between same letters
    const pairs = [];
    let i = 0;
    
    while (i < text.length) {
        if (i === text.length - 1) {
            pairs.push(text[i] + 'X');
            break;
        }
        
        if (text[i] === text[i + 1]) {
            pairs.push(text[i] + 'X');
            i++;
        } else {
            pairs.push(text[i] + text[i + 1]);
            i += 2;
        }
    }
    
    return pairs;
};

const playfairCipher = (text, key, mode) => {
    const matrix = generatePlayfairMatrix(key);
    const pairs = prepareText(text);
    let result = '';

    pairs.forEach(pair => {
        const char1 = pair[0];
        const char2 = pair[1];
        const [row1, col1] = findPosition(matrix, char1);
        const [row2, col2] = findPosition(matrix, char2);

        let newChar1, newChar2;

        if (row1 === row2) {
            // Same row
            if (mode === "encrypt") {
                newChar1 = matrix[row1][(col1 + 1) % 5];
                newChar2 = matrix[row2][(col2 + 1) % 5];
            } else {
                newChar1 = matrix[row1][(col1 - 1 + 5) % 5];
                newChar2 = matrix[row2][(col2 - 1 + 5) % 5];
            }
        } else if (col1 === col2) {
            // Same column
            if (mode === "encrypt") {
                newChar1 = matrix[(row1 + 1) % 5][col1];
                newChar2 = matrix[(row2 + 1) % 5][col2];
            } else {
                newChar1 = matrix[(row1 - 1 + 5) % 5][col1];
                newChar2 = matrix[(row2 - 1 + 5) % 5][col2];
            }
        } else {
            // Rectangle case - swap columns
            newChar1 = matrix[row1][col2];
            newChar2 = matrix[row2][col1];
        }

        result += newChar1 + newChar2;
    });

    return result;
};