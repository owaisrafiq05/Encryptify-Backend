import { encryptMessage, decryptMessage, generateKeys } from '../utils/rsaUtils.js';

// rsaEncrypt function: This handles the RSA encryption of the provided text.
export const rsaEncrypt = (req, res) => {
    // Extract text from the request body
    const { text } = req.body;

    // Check if the text is provided in the request body
    if (!text) {
        return res.status(400).json({
            message: "Text, e, and n are required for RSA encryption.",
            status: false
        });
    }

    try {
        // Generate public and secret keys for RSA encryption
        const { publicKey, secretKey } = generateKeys();
        console.log("Generated Public Key:", publicKey);
        console.log("Generated Secret Key:", secretKey);

        // Encrypt the message using the generated public key
        const encryptedMessage = encryptMessage(text, publicKey);

        // Prepare public and secret keys as strings
        const publicKeyString = {
            e: publicKey.e.toString(),
            n: publicKey.n.toString()
        };

        const secretKeyString = {
            d: secretKey.d.toString(),
            n: secretKey.n.toString()
        };

        // Respond with the encrypted message and the keys
        res.status(200).json({
            message: "Encryption successful",
            encryptedMessage,
            publicKey: publicKeyString,
            secretKey: secretKeyString,
            status: true
        });
    } catch (error) {
        // Handle errors during encryption
        res.status(500).json({
            message: error.message,
            status: false
        });
    }
};

// rsaDecrypt function: This handles the RSA decryption of the provided ciphertext.
export const rsaDecrypt = (req, res) => {
    // Extract ciphertext, d, and n from the request body
    const { cipherText, d, n } = req.body;

    // Check if the necessary parameters (cipherText, d, and n) are provided
    if (!cipherText || !d || !n) {
        return res.status(400).json({
            message: "Ciphertext, d, and n are required for RSA decryption.",
            status: false
        });
    }

    try {
        // Create the secret key object using BigInt for d and n
        const secretKey = { d: BigInt(d), n: BigInt(n) };

        // Parse the cipherText (which is an array of strings) into an array of BigInts
        const cipherArray = cipherText.map((text) => BigInt(text));

        // Decrypt the message using the secret key
        const decryptedMessage = decryptMessage(cipherArray, secretKey);

        // Respond with the decrypted message
        res.status(200).json({
            message: "Decryption successful",
            decryptedMessage,
            status: true
        });
    } catch (error) {
        // Handle errors during decryption
        res.status(500).json({
            message: error.message,
            status: false
        });
    }
};
