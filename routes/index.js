import express from "express";
import { encryptController, decryptController } from "../controllers/cipherController.js";

const route = express.Router();

// Caesar Cipher Encryption and Decryption Routes
route.post("/caesar-encrypt", encryptController);
route.post("/caesar-decrypt", decryptController);

route.get("/", (request, response) => {
  response.send("Caesar Cipher API");
});

export default route;
