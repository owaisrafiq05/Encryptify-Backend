// Helper function for API calls
const makeRequest = async (url, data) => {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      return await response.json();
    } catch (error) {
      throw new Error(`API request failed: ${error.message}`);
    }
  };
  
  // Triple DES encryption function
  const tripleDESEncrypt = async (message, key1, key2, key3) => {
    // First encryption with key1
    const firstEncryption = await makeRequest('https://encryptify-backend.vercel.app/des-encrypt', {
      message: message,
      key: key1
    });
    
    // Second decryption with key2
    const secondDecryption = await makeRequest('https://encryptify-backend.vercel.app/des-decrypt', {
      message: firstEncryption.encryptedData,
      key: key2
    });
    
    // Third encryption with key3
    const thirdEncryption = await makeRequest('https://encryptify-backend.vercel.app/des-encrypt', {
      message: secondDecryption.decryptedData,
      key: key3
    });
    
    return thirdEncryption.encryptedData;
  };
  
  // Triple DES decryption function
  const tripleDESDecrypt = async (ciphertext, key1, key2, key3) => {
    // First decryption with key3
    const firstDecryption = await makeRequest('https://encryptify-backend.vercel.app/des-decrypt', {
      message: ciphertext,
      key: key3
    });
    
    // Second encryption with key2
    const secondEncryption = await makeRequest('https://encryptify-backend.vercel.app/des-encrypt', {
      message: firstDecryption.decryptedData,
      key: key2
    });
    
    // Third decryption with key1
    const thirdDecryption = await makeRequest('https://encryptify-backend.vercel.app/des-decrypt', {
      message: secondEncryption.encryptedData,
      key: key1
    });
    
    return thirdDecryption.decryptedData;
  };
  
  // Encrypt Controller
  export const tripleDesEncryption = async (request, response) => {
    const { message, key1, key2, key3 } = request.body;
  
    if (!message || !key1 || !key2 || !key3) {
      response.json({
        message: "Message and all three keys are required.",
        status: false
      });
      return;
    }
  
    try {
      const encryptedText = await tripleDESEncrypt(message, key1, key2, key3);
      response.json({
        encryptedText,
        message: "Triple DES encryption successful.",
        status: true,
        originalMessage: message,
        keys: { key1, key2, key3 }
      });
    } catch (error) {
      response.json({
        message: "Triple DES encryption failed.",
        status: false,
        data: error.message
      });
    }
  };
  
  // Decrypt Controller
  export const tripleDesDecryption = async (request, response) => {
    const { ciphertext, key1, key2, key3 } = request.body;
  
    if (!ciphertext || !key1 || !key2 || !key3) {
      response.json({   
        message: "Ciphertext and all three keys are required.",
        status: false
      });
      return;
    }
  
    try {
      const decryptedText = await tripleDESDecrypt(ciphertext, key1, key2, key3);
      response.json({
        decryptedText,
        message: "Triple DES decryption successful.",
        status: true,
        originalCiphertext: ciphertext,
        keys: { key1, key2, key3 }
      });
    } catch (error) {
      response.json({
        message: "Triple DES decryption failed.",
        status: false,
        data: error.message
      });
    }
  };
 