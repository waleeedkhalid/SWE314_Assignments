const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Path to store the key and IV
const keyFilePath = path.join(__dirname, 'key_iv.json');

// Function to generate and save key and IV
const generateAndSaveKeyIV = () => {
  const key = crypto.randomBytes(32); // 256-bit key
  const iv = crypto.randomBytes(16); // 128-bit IV

  // Convert key and IV to hex strings and save them in a JSON file
  const keyIVData = {
    key: key.toString("hex"),
    iv: iv.toString("hex"),
  };

  fs.writeFileSync(keyFilePath, JSON.stringify(keyIVData));

  return keyIVData;
};

// Function to load key and IV from file, or generate if not present
const loadKeyIV = () => {
  if (fs.existsSync(keyFilePath)) {
    const keyIVData = JSON.parse(fs.readFileSync(keyFilePath, "utf8"));
    return {
      key: Buffer.from(keyIVData.key, "hex"),
      iv: Buffer.from(keyIVData.iv, "hex"),
    };
  } else {
    return generateAndSaveKeyIV();
  }
};

// Load key and IV
const { key, iv } = loadKeyIV();

// Function to encrypt a given text
const encrypt = (text) => {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
};

// Function to decrypt a given piece of encrypted text
const decrypt = (encrypted) => {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
};

// Example usage
// const text = "secret";
// const encrypted = encrypt(text);
// const decrypted = decrypt(encrypted);

// Log the original, encrypted, and decrypted texts
// console.log("Original:", text);
// console.log("Encrypted:", encrypted);
// console.log("Decrypted:", decrypted);

module.exports = {
  encrypt,
  decrypt,
  loadKeyIV
}
