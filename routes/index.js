import express from "express";
import { encryptController, decryptController } from "../controllers/cipherController.js";
import { encryptRailFence, decryptRailFence } from "../controllers/RailFenceController.js";
import { vigenereEncrypt, vigenereDecrypt } from "../controllers/vigenereCipher.js";
import { vernamEncrypt, vernamDecrypt } from "../controllers/vernamCipher.js";
import { playfairEncrypt , playfairDecrypt } from "../controllers/playFairCipher.js"
import { aesEncrypt, aesDecrypt } from '../controllers/aesCipher.js'; 
import { rsaEncrypt, rsaDecrypt } from '../controllers/rsaCipher.js'; 
import {hashController} from '../controllers/sha256Controller.js';
import {sha512Controller} from '../controllers/sha512Controller.js';



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
route.post('/aes-encrypt', aesEncrypt);
route.post('/aes-decrypt', aesDecrypt);
route.post('/rsa-encrypt',rsaEncrypt);
route.post('/rsa-decrypt',rsaDecrypt);
route.post('/sha-256Hash',hashController);
route.post('/sha-512Hash',sha512Controller);

export default route;
