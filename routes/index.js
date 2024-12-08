import express from "express";
import { encryptController, decryptController } from "../controllers/cipherController.js";
import { encryptRailFence, decryptRailFence } from "../controllers/RailFenceController.js";
import { vigenereEncrypt, vigenereDecrypt } from "../controllers/vigenereCipher.js";
import { vernamEncrypt, vernamDecrypt } from "../controllers/vernamCipher.js";
import { playfairEncrypt , playfairDecrypt } from "../controllers/playFairCipher.js"
import { aesEncryption, aesDecryption } from '../controllers/aesCipher.js'; 
import { rsaEncrypt, rsaDecrypt } from '../controllers/rsaCipher.js'; 
import {hashController} from '../controllers/sha256Controller.js';

import { desEncrypt, desDecrypt } from '../controllers/desCipher.js'; 
import { sha0Hash } from "../controllers/SHA-0.js";
import {sha1Hash} from "../controllers/SHA-1.js";
import { sha3Hash } from '../controllers/SHA-3.js';
import { tripleDesDecryption,tripleDesEncryption } from "../controllers/tripleDesCipher.js";
// import {hash512} from '../controllers/sha512Controller.js';
import { sha512Hash } from '../controllers/sha512Controller.js';
import { sha224Hash } from '../controllers/sha224Controller.js';
import { sha384Hash } from "../controllers/sha384Controller.js";
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
route.post('/aes-encrypt', aesEncryption);
route.post('/aes-decrypt', aesDecryption);
route.post('/rsa-encrypt',rsaEncrypt);
route.post('/rsa-decrypt',rsaDecrypt);
route.post('/des-encrypt', desEncrypt);
route.post('/des-decrypt', desDecrypt);
route.post('/3des-encrypt', tripleDesEncryption);
route.post('/3des-decrypt', tripleDesDecryption);

route.post('/sha-512Hash',sha512Hash);
route.post("/sha0-hash", sha0Hash);
route.post("/sha1-hash", sha1Hash);
route.post("/sha-3Hash", sha3Hash);
route.post('/sha-256Hash',hashController);
route.post('/sha-224Hash',sha224Hash);
route.post('/sha-384Hash',sha384Hash);


export default route;