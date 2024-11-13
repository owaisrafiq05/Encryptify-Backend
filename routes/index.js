import express from "express";
import { encryptController, decryptController } from "../controllers/cipherController.js";
import { encryptRailFence, decryptRailFence } from "../controllers/RailFenceController.js";
import { vigenereEncrypt, vigenereDecrypt } from "../controllers/vigenereCipher.js";
import { vernamEncrypt, vernamDecrypt } from "../controllers/vernamCipher.js";
import { playfairEncrypt , playfairDecrypt } from "../controllers/playFairCipher.js"

const route = express.Router();

// Caesar Cipher Encryption and Decryption Routes
route.post("/caesar-encrypt", encryptController);
route.post("/caesar-decrypt", decryptController);
route.post("/rail-fence-encrypt", encryptRailFence);
route.post("/rail-fence-decrypt", decryptRailFence);
route.post("/vigenere-encrypt", vigenereEncrypt);
route.post("/vigenere-decrypt", vigenereDecrypt);
route.post("/vernam-encrypt", vernamEncrypt);
route.post("/vernam-decrypt", vernamDecrypt);
route.post("/playfair-encrypt", playfairEncrypt);
route.post("/playfair-decrypt", playfairDecrypt);

export default route;
