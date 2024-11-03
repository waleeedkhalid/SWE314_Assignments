const express = require("express");
const rateLimit = require('express-rate-limit');
const path = require("path");
const app = express();
const port = 3000;
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);
const database = require("./database/database.js"); 

const { authenticator } = require('otplib');

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
	standardHeaders: 'draft-7', // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
});

// Apply the rate limiting middleware to all requests.
app.use(limiter)

app.use('/', express.static(path.join(__dirname, 'public', 'login')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup')));

const { decrypt, encrypt } = require('./encrypt.js');


app.post('/login', (req, res) => {
  const { username, password, otp } = req.body;

  const user = {
    username: username,
    passwordToCheck: password,
    otp
  }

  database.authenticate(user)
  .then((result) => 
  {
    if(result){
      const userSecret = result.twoFactorSecret;
      if(!userSecret) {
        // res.json(result);
        res.send(`
          <html>
  <head>
    <style>
      body {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100vh;
        margin: 0;
        font-family: Arial, sans-serif;
        background-color: #f0f0f0;
      }
      .profile-container {
        background-color: #fff;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        width: 300px;
        text-align: center;
      }
      .profile-header {
        font-size: 1.5em;
        margin-bottom: 10px;
        color: #333;
      }
      .profile-details {
        margin: 10px 0;
        color: #555;
        word-wrap: break-word;
      }
      .profile-value {
        font-weight: bold;
        color: #0066cc;
      }
    </style>
  </head>
  <body>
    <div class="profile-container">
      <div class="profile-header">Username: <span class="profile-value">${result.username}</span>!</div>
      <div class="profile-details">Password (Hashed SHA-3): <span class="profile-value">${result.password}</span></div>
      <div class="profile-details">Salt: <span class="profile-value">${result.salt}</span></div>
      <div class="profile-details">Two Factor Secret (Encrypted): <span class="profile-value">${result.twoFactorSecret}</span></div>
    </div>
  </body>
</html>
          `)
        return;
      }

      const isValid = authenticator.check(otp, decrypt(userSecret));

      if (isValid) {
        // res.json(result);
        res.send(`
          <html>
  <head>
    <style>
      body {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100vh;
        margin: 0;
        font-family: Arial, sans-serif;
        background-color: #f0f0f0;
      }
      .profile-container {
        background-color: #fff;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        width: 300px;
        text-align: center;
      }
      .profile-header {
        font-size: 1.5em;
        margin-bottom: 10px;
        color: #333;
      }
      .profile-details {
        margin: 10px 0;
        color: #555;
        word-wrap: break-word;
      }
    </style>
  </head>
  <body>
    <div class="profile-container">
      <div class="profile-header">Username: ${result.username}</div>
      <div class="profile-details">Password(Hashed SHA-3): ${result.password}</div>
      <div class="profile-details">Salt: ${result.salt}</div>
      <div class="profile-details">Two Factor Secret(Encrypted): ${result.twoFactorSecret}</div>
    </div>
  </body>
</html>

          `)
      } else {
        res.redirect('/?otpfailure=true');
      }
    }
    else{
      res.redirect('/?error=true');
    }
  })
  .catch((err) => res.redirect('/?error=true')
  )
});


const QRCode = require('qrcode');

app.post('/submitSignup', (req, res) => {
  const { username, password } = req.body;

  const userSecret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(username, 'SWE314_Assignment1', userSecret);
  
  const secret = encrypt(userSecret);

  const user = {
    username: username,
    password: password,
    secret
  }

  database.signup(user)
  .then((result) => {
    if (result) {
      QRCode.toDataURL(otpauth, (err, imageUrl) => {
        if (err) {
          console.error('Error generating QR code', err);
          res.status(500).json({ message: 'Error generating QR code' });
        } else {
          // res.json({ message: 'User created successfully!', qrCodeUrl: imageUrl });
          res.send(`
            <html>
  <head>
    <style>
      body {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 100vh;
        margin: 0;
        font-family: Arial, sans-serif;
        background-color: #f5f5f5;
      }
      h2 {
        color: #333;
      }
      p {
        color: #666;
      }
      img {
        margin: 20px 0;
        border: 2px solid #ddd;
        border-radius: 8px;
      }
      a {
        padding: 10px 20px;
        background-color: #007bff;
        color: white;
        text-decoration: none;
        border-radius: 5px;
        transition: background-color 0.3s;
      }
      a:hover {
        background-color: #0056b3;
      }
    </style>
  </head>
  <body>
    <h2>User created successfully!</h2>
    <p>Scan the QR Code below to activate 2FA (Two Factor Authentication)</p>
    <img src="${imageUrl}" alt="QR Code">
    <a href="/">Login</a>
  </body>
</html>
          `);
        }
      });
    } else {
      res.redirect('/signup?error=true');
    }
  }
  ).catch((err) => {
    console.error('Error during signup:', err);
    res.status(500).json({ message: 'Server error during signup' });
  });
});

app.get('/users', (req, res) => {
  database.users()
  .then((result) => {
    if (result.length > 0) {
      res.json(result);
    } else {
      res.redirect('/');
    }
  }
  ).catch((err) => {
    console.error('Error during users:', err);
    res.status(500).json({ message: 'Server error during users' });
  });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});