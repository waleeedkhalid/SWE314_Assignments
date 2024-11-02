const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'database.db');

const crypto = require('node:crypto');


function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.createHmac("sha512", salt).update(password).digest("hex");

  return { salt, hash };
}

function verifyPassword(storedSalt, storedHash, password) {
  const hashToCheck = crypto
  .createHmac("sha512", storedSalt)
  .update(password)
  .digest("hex");

  return hashToCheck === storedHash;
}

const validateInput = (input) => {
  const regex = /^[a-zA-Z0-9_]*$/;
  return regex.test(input);
}

const users = async () => {
  try {
  const db = await dbinit();
  const sql = `SELECT * FROM users`;

  return new Promise((resolve, reject) =>
    db.all(sql, [], (err, rows) => {
      db.close();
      return resolve(rows);
    }))
  } catch (err) {
  console.error(err);
  }
};

const authentication = async ({ username, passwordToCheck }) => {
  try {

  if(!validateInput(username) || !validateInput(passwordToCheck)) {
    console.log("Invalid input: only alphanumeric characters and underscore are allowed.");
    return null;
  }

  const db = await dbinit();
  const sql = `SELECT * FROM users WHERE username = ?`;

  return new Promise((resolve, reject) =>
    db.get(sql, [username], (err, row) => {
      db.close();
      if (err) {
        return reject(err);
      }
      
      // no user found
      if (!row) {
        return resolve(null);
      }

      console.log(row);
      if(!row.salt || !row.password) return resolve(null);
      const isPasswordValid = verifyPassword(row.salt, row.password, passwordToCheck);
      if(isPasswordValid) {
        return resolve(row);
      }

      return resolve(null);
    }
    )
  )
} catch (err) {
  console.error(err);
}
};
 
const signup = async ({ username, password, secret }) => {

  if(!validateInput(username) || !validateInput(password)) {
    console.log("Invalid input: only alphanumeric characters and underscore are allowed.");
    return null;
  }

  const db = await dbinit();
  const { salt, hash } = hashPassword(password);

  // encrypt the secret
  // const encryptedsecret = encrypt(secret);
  // add the user and password to the database
  const sql = `INSERT INTO users (username, password, salt, twoFactorSecret) VALUES (?, ?, ?, ?)`;

  return new Promise((resolve, reject) => {
    db.run(sql, [username, hash, salt, secret], function (err) {
      db.close();
      if (err) {
        // Check if the error is due to the username already existing (unique constraint violation)
        if (err.code === 'SQLITE_CONSTRAINT') {
          console.error('Username already exists.');
          return resolve(false); // Username already exists, return false
        }
        // If any other error occurs, reject the promise
        return reject(err);
      }
      
      // If insertion is successful, return true
      resolve(true);
    });
  });
};

const dbinit = async () => {
  try {
    const db = await new sqlite3.Database(dbPath);
    const sql = `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      salt TEXT,
      twoFactorSecret TEXT
    )`;
    db.run(sql);
    return db;
  }
  catch (err) {
    console.log(err);
    throw err;
  }
};

module.exports = {
  authenticate: authentication,
  signup: signup,
  users,
};