var mysql = require('mysql');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
var ReCaptchaVerify = require('recaptcha-verify');
var recaptcha = new ReCaptchaVerify({
    secret: '6Le5zIQjAAAAACV1K7I7b9qcYjrURlVwPY07lpVM',
    verbose: true
});
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require("cookie-parser");
const cors = require('cors');
const app = express();
const admins = ["alex_dalas@outlook.com"];

app.use(cors({
    origin: 'http://127.0.0.1:3030',
    credentials: true,
  }));

app.use(bodyParser.json());
app.use(cookieParser());

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

con.query(`CREATE TABLE IF NOT EXISTS users (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(255) NOT NULL, email VARCHAR(255), password VARCHAR(255), created BIGINT NOT NULL, banned BOOLEAN, PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        console.error(error);
    } //else {
        //console.log(results);
    //}
});  

con.query(`CREATE TABLE IF NOT EXISTS tokens (id INT NOT NULL AUTO_INCREMENT, token VARCHAR(255) NOT NULL, user VARCHAR(255) NOT NULL, PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        console.error(error);
    } //else {
        //console.log(results);
    //}
});  

con.query(`CREATE TABLE IF NOT EXISTS posts (id INT NOT NULL AUTO_INCREMENT, user VARCHAR(255) NOT NULL, header VARCHAR(255) NOT NULL, contents LONGTEXT NOT NULL, timestamp BIGINT NOT NULL, PRIMARY KEY(id));`, (error, results) => {
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
  
function usernameTaken(username){
    return new Promise((resolve, reject) => {
        con.query('SELECT COUNT(*) FROM users WHERE name = ?', [username], (error, results) => {
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

function createPost(email, header, contents){  
    return new Promise((resolve, reject) => {
        con.query('INSERT INTO posts (email, header, contents) VALUES (?, ?, ?)', [email, header, contents], (error, results) => {
            if (error) {
                console.error(error);
                resolve(500);
            } else {
                //console.log(results);
                resolve(200);
            }
        });
    });
}

function getPost(id){
    //get posts, get post author id (for linking to user url, to show all posts by author)
    return new Promise((resolve, reject) => {
        
    });
}

function createUser(name, email, password){  
    return new Promise((resolve, reject) => {
        accountExists(email).then(result => {
            if (result){
                resolve(409);
            }
            else{
                usernameTaken(name).then(result => {
                    if (result){
                        resolve(408);
                    }
                    else{
                        hashPassword(password).then((hashedPassword) => {
                            console.log(hashedPassword);
                            con.query('INSERT INTO users (name, email, password, created, banned) VALUES (?, ?, ?, ?, ?)', [name, email, hashedPassword, Date.now(), false], (error, results) => {
                                if (error) {
                                    console.error(error);
                                    resolve(500);
                                } else {
                                    //console.log(results);
                                    resolve(200);
                                }
                            });
                        });
                    }
                });
            }
        });
      });
}

function validateUser(email, password){  
    return new Promise((resolve, reject) => {
        accountExists(email).then(result => {
            if (result){
                console.log("User found");
                con.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
                    validatePassword(password, results[0].password).then(isValid => {
                        if (isValid) {
                            console.log("Password is correct")
                            resolve(200);
                        } else{
                            console.log("Password is incorrect")
                            resolve(404);
                        }
                    });
                });
            }
            else{
                resolve(409);
            }
        }).catch(err =>{
            resolve(500);
        });
    });
}

function checkToken(token){  
    return new Promise((resolve, reject) => {
        try{
            console.log(token);
            con.query('SELECT * FROM tokens WHERE token = ?', [token], (error, results) => {
                if (results[0]){
                    con.query('SELECT * FROM users WHERE email = ?', [results[0].user], (error, results) => {
                        if (results[0]){
                            resolve(results[0].email);
                        }
                        else{
                            resolve(500);
                        }
                    });
                }
                else{
                    resolve(500);
                }
            });
        }catch{
            resolve(500);
        }
    });
}

app.post('/login', (req, res) => {
    console.log(req.body);
    validateUser(req.body.email, req.body.password).then(result => {
        switch(result) {
            case 409:
                res.json({ code: 409 });
                break;
            case 404:
                res.json({ code: 404 });
                break;
            case 200:
                var tk = "";
                res.json({ code: 200, token: tk });
                break;
            default:
                res.json({ code: 500 });
                break;
        } 
    });/*

    var userResponse = req.query['g-recaptcha-response'];
 
    recaptcha.checkResponse(userResponse, function(error, response){
        if(error){
            // an internal error?
            res.status(400).render('400', {
                message: error.toString()
            });
            return; 
        }
        if(response.success){
            res.status(200).send('the user is a HUMAN :)');
            // save session.. create user.. save form data.. render page, return json.. etc.
        }else{
            res.status(200).send('the user is a ROBOT :(');
            // show warning, render page, return a json, etc.
        }
    });*/
});

app.post('/signup', (req, res) => {
    console.log(req.body);
    createUser(req.body.username, req.body.email, req.body.password).then(result => {
        switch(result) {
            case 409:
                res.json({ code: 409 });
                break;
            case 408:
                res.json({ code: 408 });
                break;
            case 200:
                res.json({ code: 200 });
                break;
            default:
                res.json({ code: 500 });
                break;
        } 
    });
    /*var userResponse = req.query['g-recaptcha-response'];
 
    recaptcha.checkResponse(userResponse, function(error, response){
        if(error){
            // an internal error?
            res.status(400).render('400', {
                message: error.toString()
            });
            return; 
        }
        if(response.success){
            res.status(200).send('the user is a HUMAN :)');
            // save session.. create user.. save form data.. render page, return json.. etc.
        }else{
            res.status(200).send('the user is a ROBOT :(');
            // show warning, render page, return a json, etc.
        }
    });*/
});

app.post('/token', (req, res) => {
    checkToken(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query('SELECT * FROM users WHERE email = ?', [data], (error, results) => {
                if (results){
                    res.json({ code: 200, name: results[0].name, email: results[0].email, id: results[0].id })
                }
                else{
                    res.json({ code: 500 });
                }
            });
        }
        else{
            res.json({ code: 404 });
        }
    });
});

app.post('/gentoken', (req, res) => {
    console.log(req.body);
    validateUser(req.body.email, req.body.password).then(result => {
        console.log(result);
        switch(result) {
            case 409:
                res.json({ code: 409 });
                break;
            case 404:
                res.json({ code: 404 });
                break;
            case 200:
                var tk = crypto.randomBytes(64).toString('hex');
                con.query('INSERT INTO tokens (token, user) VALUES (?, ?)', [tk, req.body.email], (error, results) => {
                    if (error) {
                        console.error(error);
                        res.json({ code: 500 });
                    } else {
                        console.log(crypto.randomBytes(64).toString('hex'));
                        res.json({ code: 200, token: tk });
                    }
                });
                break;
            default:
                res.json({ code: 500 });
                break;
        } 
    });/*

    var userResponse = req.query['g-recaptcha-response'];
 
    recaptcha.checkResponse(userResponse, function(error, response){
        if(error){
            // an internal error?
            res.status(400).render('400', {
                message: error.toString()
            });
            return; 
        }
        if(response.success){
            res.status(200).send('the user is a HUMAN :)');
            // save session.. create user.. save form data.. render page, return json.. etc.
        }else{
            res.status(200).send('the user is a ROBOT :(');
            // show warning, render page, return a json, etc.
        }
    });*/
});

app.post('/listpost', (req, res) => {
    if(req.body.post){
        if (req.body.post <= 0){
            res.json({ code: 500 });
        }
        console.log(req.body);
        con.query('SELECT * FROM posts WHERE id = ?', [req.body.post], (error, results) => {
            if (error || !results) {
                console.error(error);
                res.json({ code: 500 });
            } else {
                console.log(results);
                try{
                    res.json({ code: 200, header: results[0].header, content: results[0].contents, time: results[0].timestamp, user: results[0].user });
                }
                catch{
                    res.json({ code: 500 });
                }
                
            }
        });
    }
    else if(req.body.author){
        con.query('SELECT * FROM posts WHERE user = ? ORDER BY id DESC LIMIT 10', [req.body.author], (error, results) => {
            if (error || !results) {
                console.error(error);
                res.json({ code: 500 });
            } else {
                console.log(results);
                res.json({ code: 200, posts: results });
            }
        });
    }
    else{
        con.query('SELECT * FROM posts ORDER BY id;', (error, results) => {
            if (error) {
                console.error(error);
                res.json({ code: 500 });
            } else {
                console.log(results);
                res.json({ code: 200, posts: results });
            }
        });
    }
});

app.post('/createpost', (req, res) => {
    if (req.body.header == null || req.body.contents == null) {res.json({ code : 500 });}
    checkToken(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query('SELECT * FROM users WHERE email = ?', [data], (error, results) => {
                con.query('INSERT INTO posts (user, header, contents, timestamp) VALUES (?, ?, ?, ?)', [results[0].name, req.body.header, req.body.contents, Date.now()], (error) => {
                    if (error) {
                        console.error(error);
                        res.json({ code: 500 });
                    } else {
                        con.query('SELECT * FROM posts WHERE user = ? ORDER BY timestamp DESC LIMIT 1', [results[0].name], (error, results) => {
                            if (error) {
                                console.error(error);
                                res.json({ code: 500 });
                            } else {
                                console.log(results); // results is not defined
                                res.json({ code: 200, redirect: results[0].id});
                            }
                        });
                    }
                });
            });
        }
        else{
            res.json({ code: 404 });
        }  
    });
});

app.post('/listuser', (req, res) => {
    con.query('SELECT * FROM users WHERE name = ?', [req.body.name], (error, resultsName) => {
        con.query('SELECT * FROM posts WHERE user = ?', [req.body.name], (error, results) => {
            if (error || !results) {
                console.error(error);
                res.json({ code: 500 });
            } else {
                console.log(results);
                res.json({ code: 200, name: req.body.name, posts: results, creation: resultsName[0].created });
            }
        });
    });
});

app.post('/deletepost', (req, res) => {
    checkToken(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query('SELECT * FROM posts WHERE id = ?', [req.body.post], (error, resultsName) => {
                con.query('SELECT * FROM users WHERE name = ?', [resultsName[0].user], (error, UserPostName) => {
                    if (error || !resultsName || (UserPostName[0].email != data && !isAdmin(req.cookies['token']))) {
                        console.error(error);
                        res.json({ code: 500 });
                    } else {
                        con.query("DELETE FROM posts WHERE id = ?", [req.body.post], function (err, result) {
                            if (err) throw err;
                            console.log(resultsName);
                            console.log(data);
                            console.log(result.affectedRows + " record(s) deleted");
                            res.json({ code: 200 });
                        });
                    }
                });
            });
        }
        else{
            res.json({ code: 404 });
        }
    });
});

app.post('/editpost', (req, res) => {
    checkToken(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query('SELECT * FROM posts WHERE id = ?', [req.body.id], (error, resultsName) => {
                con.query('SELECT * FROM users WHERE name = ?', [resultsName[0].user], (error, UserPostName) => {
                    if (error || !resultsName || (UserPostName[0].email != data && !isAdmin(req.cookies['token']))) {
                        console.error(error);
                        res.json({ code: 500 });
                    } else {
                        con.query("UPDATE posts SET contents = ?, timestamp = ? WHERE id = ?", [req.body.contents, Date.now(), req.body.id], function (err, result) {
                            if (err) throw err;
                            console.log(result.affectedRows + " record(s) deleted");
                          });
                          res.json({ code: 200 });
                    }
                });
            });
        }
        else{
            res.json({ code: 404 });
        }
    });
});

app.post('/searchpost', (req, res) => {
    con.query('SELECT * FROM posts WHERE header LIKE ? OR user LIKE ? OR contents LIKE ? ORDER BY id;', [req.body.query, req.body.query, req.body.query], (error, results) => {
        if (error) {
            console.error(error);
            res.json({ code: 500 });
        } else {
            console.log(results);
            res.json({ code: 200, posts: results });
        }
    });
});

function isAdmin(token){
    return new Promise((resolve, reject) => {
        checkToken(token).then(data=>{
            if (data != 500 && admins.includes(data)){
                resolve(data);
            }
            else{
                resolve(500);
            }
        });
    });
}

app.post('/listusers', (req, res) => {
    isAdmin(req.cookies['token']).then(data=>{
        if (data != 500){        
            con.query('SELECT * FROM users ORDER BY id;', (error, results) => {
                if (error) {
                    console.error(error);
                    res.json({ code: 500 });
                } else {
                    console.log(results);
                    res.json({ code: 200, posts: results });
                }
            });
        }
        else{
            res.json({ code: 500 });
        }
    });
});

app.post('/isadmin', (req, res) => {
    isAdmin(req.cookies['token']).then(data=>{
        if (data != 500){
            res.json({ code: 200 });
        }
        else{
            res.json({ code: 500 });
        }
    });
});

app.post('/deleteaccount', (req, res) => {
    isAdmin(req.cookies['token']).then(data=>{
        if (data != 500){      
            con.query("SELECT * FROM users WHERE id = ?", [req.body.user], function (err, user) {   
                if (!admins.includes(user[0].email)){
                    con.query("DELETE FROM users WHERE email = ?", [user[0].email], function (err, result) {   
                        con.query("DELETE FROM tokens WHERE user = ?", [user[0].email], function (err, result) {
                            con.query("DELETE FROM posts WHERE user = ?", [user[0].name], function (err, result) {
                                if (err) throw err;
                                console.log(`Deleted user ${user[0].name}`);
                                res.json({ code: 200 });
                            });
                        });
                    });
                }else{
                    res.json({ code: 500 });
                }
            });  
        }
        else{
            res.json({ code: 500 });
        }
    });
});

app.post('/banaccount', (req, res) => {
    isAdmin(req.cookies['token']).then(data=>{
        con.query("SELECT * FROM users WHERE id = ?", [req.body.user], function (err, user) {   
            if (!admins.includes(user[0].email)){
                if (data != 500 && !admins.includes(user[0].email)){     
                    con.query("UPDATE users SET banned = NOT banned WHERE id = ?", [req.body.user], function (err, result) {
                        if (err) throw err;
                        console.log(result.affectedRows + " record(s) deleted");
                        res.json({ code: 200 });
                    });
                }
                else{
                    res.json({ code: 500 });
                }
            }else{
                res.json({ code: 500 });
            }
        });  

    });
});

app.post('/checkbanstatus', (req, res) => {
    checkToken(req.cookies['token']).then(data=>{
        try{
            if (data != 500 || req.body.user != 1){        
                con.query("SELECT banned FROM users WHERE email = ?", [data], function (err, result) {
                    if (err) throw err;
                    if (result[0]){
                        console.log(result[0].banned);
                        res.json({ code: 200+(result[0].banned*200) });
                    }
                    else{
                        res.json({ code: 200 });
                    }
                });
            }
            else{
                res.json({ code: 200 });
            }
        }
        catch{
            res.json({ code: 200 });
        }
    });
});

app.listen(3000);

