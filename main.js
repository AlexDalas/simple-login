/*
    More use of the logs
    Allow users to delete their own comments
    Allow post owners to delete other's comments
    Add a character limit to the username and passwords (technical reasons)
    Add a button that lets you close registrations
    Gifs as comments
*/

var mysql = require('mysql');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
var ReCaptchaVerify = require('recaptcha-verify');
var recaptcha = new ReCaptchaVerify({
    secret: '6Le5zIQjAAAAACV1K7I7b9qcYjrURlVwPY07lpVM',
    verbose: true
});
var ip = require("ip");
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require("cookie-parser");
const cors = require('cors');
const app = express();
const fs = require('fs');
const admins = ["alex_dalas@outlook.com"];
const { spawn } = require('child_process');
var filter = require('filter');
const httpServer = spawn('python3', ['-m', 'http.server', '3030', '--directory', 'public_html']);

app.use(cors({
    origin: 'http://'+ip.address()+':3030',
    credentials: true,
}));

fs.writeFile('public_html/ip', 'http://'+ip.address()+':3000', err => {
    if (err) {
        console.error(err);
    }
});

let fileStream;

function logData(data) {
    const date = new Date();
    const filename = `program_logs/log-${date.toISOString().slice(0, 10)}.txt`;
    if (!fileStream || filename !== fileStream.path) {
      fileStream = fs.createWriteStream(filename, { flags: 'a' });
    }
    fileStream.write(`${data}\n`);
    console.log(data);
}
const date = new Date();
logData(`---\nStarting script on ${date.toISOString().slice(0, 10)} at ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}\n---`)
function closeLog() {
    if (fileStream) {
      fileStream.end();
      fileStream = null;
    }
    process.exit();
}

process.on('SIGINT', closeLog);

app.use(bodyParser.json());
app.use(cookieParser());

yourDB = "itproj";

// Below commented code is needed for pre-setup
/*

var con = mysql.createConnection({
    host: "localhost",
    user: "alex",
    password: "TestPWD",
    uri: process.env.DATABASE_URL,
    multipleStatements: false
});

con.connect(function(err) {
    if (err) throw err;
    logData("Connected to database for pre-setup");
});

con.query(`CREATE DATABASE IF NOT EXISTS ${yourDB};`, (error, results) => {
if (error) {
    logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
} else {
    if (results.insertId){
        logData(`Created database ${yourDB}`);
    }
    else{
        logData(`Database '${yourDB}' already exists`);
    }
}
});

con.end();
*/
var con = mysql.createConnection({
    host: "localhost",
    user: "itproject",
    password: "OgFZMCENwrZTgH2uEFHz",
    database: yourDB,
    uri: process.env.DATABASE_URL,
    multipleStatements: false
});

con.query(`CREATE TABLE IF NOT EXISTS users (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(255) NOT NULL, email VARCHAR(255), password VARCHAR(255), created BIGINT NOT NULL, banned BOOLEAN, PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
    } else {
        if (!results.warningCount){
            logData(`Created table 'users'`);
        }
        else{
            logData(`Table 'users' already exists`);
        }
    }
});  

con.query(`CREATE TABLE IF NOT EXISTS tokens (id INT NOT NULL AUTO_INCREMENT, token VARCHAR(255) NOT NULL, user VARCHAR(255) NOT NULL, PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
    } else {
        if (!results.warningCount){
            logData(`Created table 'tokens'`);
        }
        else{
            logData(`Table 'tokens' already exists`);
        }
    }
});  

con.query(`CREATE TABLE IF NOT EXISTS posts (id INT NOT NULL AUTO_INCREMENT, user VARCHAR(255) NOT NULL, header VARCHAR(255) NOT NULL, contents LONGTEXT NOT NULL, timestamp BIGINT NOT NULL, PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
    } else {
        if (!results.warningCount){
            logData(`Created table 'posts'`);
        }
        else{
            logData(`Table 'posts' already exists`);
        }
    }
});  


con.query(`CREATE TABLE IF NOT EXISTS comments (id INT NOT NULL AUTO_INCREMENT, user VARCHAR(255) NOT NULL, comment LONGTEXT NOT NULL, postid INT NOT NULL, timestamp BIGINT NOT NULL, PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
    } else {
        if (!results.warningCount){
            logData(`Created table 'comments'`);
        }
        else{
            logData(`Table 'comments' already exists`);
        }
    }
});  

con.query(`CREATE TABLE IF NOT EXISTS settings (id INT NOT NULL AUTO_INCREMENT, name VARCHAR(255) NOT NULL, enabled BOOLEAN,  value VARCHAR(255), PRIMARY KEY(id));`, (error, results) => {
    if (error) {
        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
    } else {
        if (!results.warningCount){
            logData(`Created table 'posts'`);
        }
        else{
            logData(`Table 'posts' already exists`);
        }
    }
});  


function accountExists(email){
    return new Promise((resolve, reject) => {
      con.query('SELECT COUNT(*) FROM users WHERE email = ?', [email], (error, results) => {
          if (error) {
          logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
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
                logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
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
    return new Promise((resolve, reject) => {
        accountExists(email).then(result => {
            if (result){
                resolve(409);
                logData(`User ${email} tried to create an account, but already has one!`);
            }
            else{
                usernameTaken(name).then(result => {
                    if (result){
                        resolve(408);
                        logData(`User ${email} tried to create an account with the name ${name}, but that name is taken!`);
                    }
                    else{
                        hashPassword(password).then((hashedPassword) => {
                            con.query('INSERT INTO users (name, email, password, created, banned) VALUES (?, ?, ?, ?, ?)', [name, email, hashedPassword, Date.now(), false], (error, results) => {
                                if (error) {
                                    logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                                    resolve(500);
                                } else {
                                    resolve(200);
                                    logData(`User ${name} has created an account with the email ${email}`);
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
                con.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
                    validatePassword(password, results[0].password).then(isValid => {
                        if (isValid) {
                            resolve(200);
                        } else{
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
    validateUser(req.body.email, req.body.password).then(result => {
        switch(result) {
            case 409:
                logData(`Authentication failed for ${req.body.email} (Does not exist)`);
                res.json({ code: 409 });
                break;
            case 404:
                logData(`Authentication failed for ${req.body.email} (Wrong password)`);
                res.json({ code: 404 });
                break;
            case 200:
                var tk = "";
                logData(`Authenticated ${req.body.email}`);
                res.json({ code: 200, token: tk });
                break;
            default:
                logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
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
    con.query("SELECT * FROM settings WHERE name = ?;", ["regOpen"], function (err, result) {
        if (err || !result[0].enabled) {
            res.json({ code: 501 });
        }else{
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
        }
    });
});

app.post('/token', (req, res) => {
    const ip = req.ip;
    checkToken(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query('SELECT * FROM users WHERE email = ?', [data], (error, results) => {
                if (results){
                    logData(`${ip} (${results[0].name}) has accessed ${req.path}`);
                    res.json({ code: 200, name: results[0].name, email: results[0].email, id: results[0].id })
                }
                else{
                    logData(`${ip} is not logged in`);
                    res.json({ code: 500 });
                }
            });
        }
        else{
            logData(`${ip} (not logged in) has accessed ${req.path}`);
            res.json({ code: 404 });
        }
    });
});

app.post('/gentoken', (req, res) => {
    validateUser(req.body.email, req.body.password).then(result => {
        switch(result) {
            case 409:
                logData(`User could not be validated`);
                res.json({ code: 409 });
                break;
            case 404:
                logData(`User could not be validated`);
                res.json({ code: 404 });
                break;
            case 200:
                var tk = crypto.randomBytes(64).toString('hex');
                con.query('INSERT INTO tokens (token, user) VALUES (?, ?)', [tk, req.body.email], (error, results) => {
                    if (error) {
                        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                        res.json({ code: 500 });
                    } else {
                        logData(`Generated token "${tk}" for user ${req.body.email}`);
                        res.json({ code: 200, token: tk });
                    }
                });
                break;
            default:
                logData(`----------\nERROR OCCURED (2)\n----------\n`);
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
        con.query('SELECT * FROM posts WHERE id = ?', [req.body.post], (error, results) => {
            if (error || !results) {
                if (results) {logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);}
                res.json({ code: 500 });
            } else {
                try{
                    isAdmin(req.cookies['token']).then(data=>{
                        if (data != 500){        
                            res.json({ code: 200, header: results[0].header, content: results[0].contents, time: results[0].timestamp, user: results[0].user, canDel: true });
                        }
                        else{
                            res.json({ code: 200, header: results[0].header, content: results[0].contents, time: results[0].timestamp, user: results[0].user, canDel: false });
                        }
                    });
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
                if (results) {logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);}
                res.json({ code: 500 });
            } else {
                res.json({ code: 200, posts: results });
            }
        });
    }
    else{
        con.query('SELECT * FROM posts ORDER BY id;', (error, results) => {
            if (error) {
                logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                res.json({ code: 500 });
            } else {
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
                con.query('SELECT timestamp FROM posts WHERE user = ? ORDER BY timestamp DESC LIMIT 1;', [results[0].name], (error, results2) => {
                    if (error) {
                        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                        res.json({ code: 500 });
                    } else {
                        var timestamp = 0;
                        try{timestamp = results2[0].timestamp;}
                        catch{timestamp = 0;}
                        if (timestamp <= (Date.now() - 200000)){
                            con.query('INSERT INTO posts (user, header, contents, timestamp) VALUES (?, ?, ?, ?)', [results[0].name, req.body.header, req.body.contents, Date.now()], (error) => {
                                if (error) {
                                    logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                                    res.json({ code: 500 });
                                } else {
                                    con.query('SELECT * FROM posts WHERE user = ? ORDER BY timestamp DESC LIMIT 1', [results[0].name], (error, results) => {
                                        if (error) {
                                            logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                                            res.json({ code: 500 });
                                        } else {
                                            res.json({ code: 200, redirect: results[0].id});
                                        }
                                    });
                                }
                            });
                        }
                        else{
                            res.json({ code: 501 });
                        }
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
                if (results){logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);}
                res.json({ code: 500 });
            } else {
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
                    if (error){
                        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                        res.json({ code: 500 });
                    } else if (!resultsName || (UserPostName[0].email != data && !isAdmin(req.cookies['token']))) {
                        res.json({ code: 500 });
                    } else {
                        con.query("DELETE FROM posts WHERE id = ?", [req.body.post], function (err, result) {
                            if (err) throw err;
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
                    if (error){
                    logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                } else if (!resultsName || (UserPostName[0].email != data && !isAdmin(req.cookies['token']))) {
                        res.json({ code: 500 });
                    } else {
                        con.query("UPDATE posts SET contents = ?, timestamp = ? WHERE id = ?", [req.body.contents, Date.now(), req.body.id], function (err, result) {
                            if (err) throw err;
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
            logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
            res.json({ code: 500 });
        } else {
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
                    logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                    res.json({ code: 500 });
                } else {
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
                                con.query("DELETE FROM comments WHERE user = ?", [user[0].name], function (err, result) {
                                    if (err) throw err;
                                    res.json({ code: 200 });
                                });
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

app.post('/comment', (req, res) => {
    if (req.body.comment == null) {res.json({ code : 500 });}
    checkToken(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query('SELECT * FROM users WHERE email = ?', [data], (error, results) => {
                con.query('SELECT timestamp FROM comments WHERE user = ? ORDER BY timestamp DESC LIMIT 1;', [results[0].name], (error, results2) => {
                    if (error) {
                        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                        res.json({ code: 500 });
                    } else {
                        var timestamp = 0;
                        try{timestamp = results2[0].timestamp;}
                        catch{timestamp = 0;}
                        if (timestamp <= (Date.now() - 120000)){
                            con.query('INSERT INTO comments (user, comment, postid, timestamp) VALUES (?, ?, ?, ?)', [results[0].name, req.body.comment, req.body.postid, Date.now()], (error) => {
                                if (error) {
                                    logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                                    res.json({ code: 500 });
                                } else {
                                    if (error) {
                                        logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
                                        res.json({ code: 500 });
                                    } else {
                                        res.json({ code: 200});
                                    }
                                }
                            });
                        }
                        else{
                            res.json({ code: 501 });
                        }
                    }
                });
            });
        }
        else{
            res.json({ code: 404 });
        }  
    });
});
app.post('/listcomments', (req, res) => {
    con.query('SELECT * FROM comments WHERE postid = ? ORDER BY timestamp DESC;', [req.body.postid], (error, results) => {
        if (error) {
            logData(`----------\nERROR OCCURED\n----------\n${error}\n----------\n`);
            res.json({ code: 500 });
        } else {
            res.json({ code: 200, posts: results });
        }
    });
});

app.post('/deletecomment', (req, res) => {
    isAdmin(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query("DELETE FROM comments WHERE id = ?", [req.body.commentid], function (err, result) {
                if (err) throw err;
                res.json({ code: 200 });
            });
        }
        else{
            res.json({ code: 404 });
        }
    });
});

con.query("INSERT INTO settings IF NOT EXISTS (name, enabled) VALUES (?, ?)", ["regOpen", true], function (err, result) {});

app.post('/getreg', (req, res) => {
    isAdmin(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query("SELECT * FROM settings WHERE name = ?;", ["regOpen"], function (err, result) {
                if (err || !result[0].enabled) {
                    res.json({ code: 400 });
                }else{
                    res.json({ code: 200 });
                }
            });
        }
        else{
            res.json({ code: 404 });
        }
    });
});
app.post('/togglereg', (req, res) => {
    isAdmin(req.cookies['token']).then(data=>{
        if (data != 500){
            con.query("UPDATE settings SET enabled = NOT enabled WHERE name = ?", ["regOpen"], function (err, result) {
                if (err) throw err;
                res.json({ code: 200 });
            });
        }
        else{
            res.json({ code: 404 });
        }
    });
});

httpServer.stdout.on('data', (data) => {
    logData(`HTTP.SERVER: ${data}`)
});

httpServer.on('close', (data) => {
    logData(`HTTP.SERVER exited with code ${data}`)
});

app.listen(3000);
logData("You can access the website at http://" + ip.address() + ":3030" );

