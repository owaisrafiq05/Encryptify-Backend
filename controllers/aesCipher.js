import CryptoJS from 'crypto-js';

// AES Encryption function
const aesEncrypt = (text, secretKey) => {
  return CryptoJS.AES.encrypt(text, secretKey).toString();
};

// AES Decryption function
const aesDecrypt = (cipherText, secretKey) => {
  const bytes = CryptoJS.AES.decrypt(cipherText, secretKey);
  return bytes.toString(CryptoJS.enc.Utf8);
};

// Encrypt Controller
export const aesEncryption = async (request, response) => {
  const { text, secretKey } = request.body;

  if (!text || !secretKey) {
    response.json({
      message: "Text and secret key are required.",
      status: false,
    });
    return;
  }

  try {
    const encryptedText = aesEncrypt(text, secretKey);
    response.json({
      encryptedText,
      message: "Encryption successful.",
      status: true,
    });
  } catch (error) {
    response.json({
      message: "Encryption failed.",
      status: false,
      data: error.message,
    });
  }
};

// Decrypt Controller
export const aesDecryption = async (request, response) => {
  const { cipherText, secretKey } = request.body;

  if (!cipherText || !secretKey) {
    response.json({
      message: "Cipher text and secret key are required.",
      status: false,
    });
    return;
  }

  try {
    const decryptedText = aesDecrypt(cipherText, secretKey);
    if (!decryptedText) {
      throw new Error("Decryption failed. Invalid key or corrupted data.");
    }
    response.json({
      decryptedText,
      message: "Decryption successful.",
      status: true,
    });
  } catch (error) {
    response.json({
      message: "Decryption failed.",
      status: false,
      data: error.message,
    });
  }
};
