// Caesar Cipher encryption function
const caesarEncrypt = (text, shift) => {
  return text.replace(/[a-zA-Z]/g, (char) => {
    const charCode = char.charCodeAt();
    const isUpperCase = charCode >= 65 && charCode <= 90;
    const offset = isUpperCase ? 65 : 97;
    return String.fromCharCode(((charCode - offset + shift) % 26) + offset);
  });
};

// Caesar Cipher decryption function
const caesarDecrypt = (text, shift) => {
  return caesarEncrypt(text, 26 - (shift % 26));
};

// Encrypt Controller
export const encryptController = async (request, response) => {
  const { text, shift } = request.body;

  if (!text || shift == null) {
    response.json({
      message: "Text and shift are required.",
      status: false,
    });
    return;
  }

  try {
    const encryptedText = caesarEncrypt(text, shift);
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
export const decryptController = async (request, response) => {
  const { text, shift } = request.body;

  if (!text || shift == null) {
    response.json({
      message: "Text and shift are required.",
      status: false,
    });
    return;
  }

  try {
    const decryptedText = caesarDecrypt(text, shift);
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
