import {  encryptMessage, decryptMessage,generateKeys } from '../utils/rsaUtils.js';

export const rsaEncrypt = (req, res) => {
    const { text } = req.body;

    if (!text) {
        return res.status(400).json({
            message: "Text, e, and n are required for RSA encryption.",
            status: false
        });
    }

    try {
        const { publicKey, secretKey } = generateKeys();
        console.log("Generated Public Key:", publicKey);
        console.log("Generated Secret Key:", secretKey);
        const encryptedMessage = encryptMessage(text, publicKey);
        const publicKeyString = {
            e: publicKey.e.toString(),
            n: publicKey.n.toString()
        };

        const secretKeyString = {
            d: secretKey.d.toString(),
            n: secretKey.n.toString()
        };
        res.status(200).json({
            message: "Encryption successful",
            encryptedMessage,
            publicKey: publicKeyString,
            secretKey: secretKeyString,
            status: true
        });
    } catch (error) {
        res.status(500).json({
            message: error.message,
            status: false
        });
    }
};

export const rsaDecrypt = (req, res) => {
    const { cipherText, d, n } = req.body;

    if (!cipherText || !d || !n) {
        return res.status(400).json({
            message: "Ciphertext, d, and n are required for RSA decryption.",
            status: false
        });
    }

    try {
        const secretKey = { d: BigInt(d), n: BigInt(n) };

        // Parse cipherText to an array of BigInt
        const cipherArray = cipherText.map((text) => BigInt(text));

        // Decrypt the array of ciphertext values
        const decryptedMessage = decryptMessage(cipherArray, secretKey);

        res.status(200).json({
            message: "Decryption successful",
            decryptedMessage,
            status: true
        });
    } catch (error) {
        res.status(500).json({
            message: error.message,
            status: false
        });
    }
};
