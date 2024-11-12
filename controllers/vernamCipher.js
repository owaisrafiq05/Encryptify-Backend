// Vernam Cipher Encryption and Decryption Controller

export const vernamEncrypt = (req, res) => {
    const { text, key } = req.body;

    // Validation for text and key
    if (!text || !key) {
        return res.status(400).json({
            message: "Text and key are required for Vernam encryption.",
            status: false
        });
    }
    
    // Ensure text and key are of equal length
    if (text.length !== key.length) {
        return res.status(400).json({
            message: "Text and key must be of equal length for Vernam encryption.",
            status: false
        });
    }

    try {
        const encryptedText = vernamCipher(text, key, "encrypt");
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

export const vernamDecrypt = (req, res) => {
    const { text, key } = req.body;

    // Validation for text and key
    if (!text || !key) {
        return res.status(400).json({
            message: "Text and key are required for Vernam decryption.",
            status: false
        });
    }
    
    // Ensure text and key are of equal length
    if (text.length !== key.length) {
        return res.status(400).json({
            message: "Text and key must be of equal length for Vernam decryption.",
            status: false
        });
    }

    try {
        const decryptedText = vernamCipher(text, key, "decrypt");
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

// Vernam Cipher Function without Base64 Encoding
const vernamCipher = (text, key, mode) => {
    const getCharNumber = char => char.toUpperCase().charCodeAt(0) - 65; // Convert A-Z to 1-26
    const getCharFromNumber = num => String.fromCharCode((num % 26) + 65); // Convert 1-26 back to A-Z
    let result = "";

    for (let i = 0; i < text.length; i++) {
        const textNum = getCharNumber(text[i]);
        const keyNum = getCharNumber(key[i]);
        const xorNum = textNum ^ keyNum; // XOR the numbers
        const cipherChar = getCharFromNumber(xorNum); // Map to A-Z range
        result += cipherChar;
    }

    return result;
};