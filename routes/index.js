import express from "express";
import { encryptController, decryptController } from "../controllers/cipherController.js";
import { encryptRailFence, decryptRailFence } from "../controllers/RailFenceController.js";
import { vigenereEncrypt, vigenereDecrypt } from "../controllers/vigenereCipherController.js";


const route = express.Router();

// Caesar Cipher Encryption and Decryption Routes
route.post("/caesar-encrypt", encryptController);
route.post("/caesar-decrypt", decryptController);
route.post("/rail-fence-encrypt", encryptRailFence);
route.post("/rail-fence-decrypt", decryptRailFence);
route.post("/vigenere-encrypt", vigenereEncrypt);
route.post("/vigenere-decrypt", vigenereDecrypt);

export default route;
