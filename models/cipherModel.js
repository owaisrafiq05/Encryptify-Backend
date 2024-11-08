import mongoose from "mongoose";

const CipherSchema = new mongoose.Schema({
  text: {
    type: String,
    required: true,
  },
  shift: {
    type: Number,
    required: true,
  },
});

export const CipherModel = mongoose.model("Cipher", CipherSchema);
