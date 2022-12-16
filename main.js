var mysql = require('mysql');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { ReCaptchaVerify } = require('recaptcha-verify');
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
    origin: 'https://127.0.0.1:3000'
  }));



yourDB = "testAPP";

var con = mysql.createConnection({
    host: "localhost",
    user: "alex",
    password: "TestPWD",
    uri: process.env.DATABASE_URL,
    multipleStatements: false
});

con.connect(function(err) {
    if (err) throw err;
    console.log("Connected!");
});

con.query(`CREATE DATABASE IF NOT EXISTS ${yourDB};`, (error, results) => {
if (error) {
    console.error(error);
} else {
    //console.log(results);
}
});

con.end();

var con = mysql.createConnection({
    host: "localhost",
    user: "alex",
    password: "TestPWD",
    database: yourDB,
    uri: process.env.DATABASE_URL,
    multipleStatements: false
});

con.query(`CREATE TABLE IF NOT EXISTS users (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(255) NOT NULL, email VARCHAR(255), password VARCHAR(255), verified BOOLEAN, PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        console.error(error);
    } //else {
        //console.log(results);
    //}
});  

function accountExists(email){
  return new Promise((resolve, reject) => {
    con.query('SELECT COUNT(*) FROM users WHERE email = ?', [email], (error, results) => {
        if (error) {
        console.error(error);
        resolve(false);
        } else {
        const count = results[0]['COUNT(*)'];          
        resolve((count > 0));
        }
    });
});
}

async function hashPassword(password) {
    const salt = await bcrypt.genSalt(10)
    const hash = await bcrypt.hash(password, salt);
    return hash;
}

function validatePassword(plainTextPassword, hashedPassword) {
    return bcrypt.compare(plainTextPassword, hashedPassword).then(isValid => {
      return isValid;
    });
  }

function createUser(name, email, password){  
    accountExists(email).then(result => {
        if (result){
            console.log("A");
            return 409;
        }
        else{
            hashPassword(password).then((hashedPassword) => {
                console.log(hashedPassword);
                con.query('INSERT INTO users (name, email, password, verified) VALUES (?, ?, ?, ?)', [name, email, hashedPassword, false], (error, results) => {
                    if (error) {
                        console.error(error);
                        return 500;
                    } else {
                        //console.log(results);
                        return 200;
                    }
                });
            });
        }
    });
}

function validateUser(email, password){  
    accountExists(email).then(result => {
        if (result){
            console.log("User found");
            con.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
                validatePassword(password, results[0].password).then(isValid => {
                    if (isValid) {
                        console.log("Password is correct")
                        return 200;
                    } 
                });
            });
            return 404;
        }
        else{
            return 409;
        }
    });
}

createUser("Alex", "alex@alexdalas.com", "Bruh");
validateUser("alex@alexdalas.com", "Bruh");


app.post('/login', async (req, res) => {
    //res.send(200);
    const recaptcha = new ReCaptchaVerify({
      secret: '6Le5zIQjAAAAACV1K7I7b9qcYjrURlVwPY07lpVM', // Replace with your secret key
      response: req.body['g-recaptcha-response']
    });
  
    try {
      const result = await recaptcha.verify();
      if (result.success) {
        res.send(200);
      } else {
        res.send(400);
      }
    } catch (error) {
      res.send(500);
    }
});

app.listen(3000);

