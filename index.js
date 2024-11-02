const express = require("express");
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
        res.json(result);
        return;
      }

      const isValid = authenticator.check(otp, decrypt(userSecret));

      if (isValid) {
        res.json(result);
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
          res.json({ message: 'User created successfully!', qrCodeUrl: imageUrl });
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