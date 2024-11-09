// Vigenere Cipher Encryption and Decryption Controller

export const vigenereEncrypt = (req, res) => {
    const { text, key } = req.body;

    if (!text || !key) {
        return res.status(400).json({
            message: "Text and key are required for encryption.",
            status: false
        });
    }

    try {
        const encryptedText = vigenereCipher(text, key, "encrypt");
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

export const vigenereDecrypt = (req, res) => {
    const { text, key } = req.body;

    if (!text || !key) {
        return res.status(400).json({
            message: "Text and key are required for decryption.",
            status: false
        });
    }

    try {
        const decryptedText = vigenereCipher(text, key, "decrypt");
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

// Vigenere Cipher Function
const vigenereCipher = (text, key, mode) => {
    let result = "";
    const upperText = text.toUpperCase();
    const upperKey = key.toUpperCase();

    let keyIndex = 0;
    for (let i = 0; i < upperText.length; i++) {
        const char = upperText[i];

        // Only encrypt/decrypt alphabetic characters
        if (char.match(/[A-Z]/)) {
            const textCharCode = char.charCodeAt(0) - 65;
            const keyCharCode = upperKey[keyIndex % upperKey.length].charCodeAt(0) - 65;
            let newCharCode;

            if (mode === "encrypt") {
                newCharCode = (textCharCode + keyCharCode) % 26;
            } else if (mode === "decrypt") {
                newCharCode = (textCharCode - keyCharCode + 26) % 26;
            }

            result += String.fromCharCode(newCharCode + 65);
            keyIndex++;
        } else {
            // Non-alphabet characters remain unchanged
            result += char;
        }
    }

    return result;
};
