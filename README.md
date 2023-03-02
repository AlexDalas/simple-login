# simple-login

This was a school project, which served as a simple posting system.

It allows for users to post and comment on anyones post, while admins can ban, delete, or edit user's profiles or posts.

This app is a demonstration of how you can create an application with tokens and authentication, and should only be used as an example or reference.

If you don't really care about that, and want to take to code, just know that it should only really be used in trusted environments, unless you audit the security of the app yourself (remember, a school project)

The app was created with MySQL, Tailwind CSS, HTML / CSS / JS, and NodeJS.

# Setup

To set up an environment, you will need NodeJS and a MySQL server

Serve public_html using the platform of your choice (Apache, Nginx, python3 http.server, etc)

Download all of the code, run 'npm install', and then run the main.js file (with npm run start). 

Edit all of the HTML files to point the HTML to your main.js, as well as the main.js server to point to your MySQL databse.

You might have to make a "cert.crt" and "pk.key" file in the root of the directory, these will serve as a HTTPS certificate and Private Key.

You now have the code set up. The rest is up to you.

# Apps, frameworks, and coding languages used.

Node JS, the coding language that runs the back-end code.
    Javascript is the language used in Node JS, Node JS is what runs the JS code.
HTML for creating the bare-bones of the front-end of the website.
    Tailwind CSS for providing a easy-to-use framework to create modern websites, which changes this bare-bones website and makes it look complete.
    Javascript for connecting the front-end to the back-end, using HTML requests, as well as letting me do whatever I want with the output of requests.
MySQL for storing information in a secure manner.

CKEditor (WYSIWYG editor, which is what is used to create the content inside of posts)
Google reCAPTCHA, which helps me keep the website secure
NPM packages, which were vital:
    ExpressJS, which provides a framework for getting information through GET and POST requests.
    Profanity-filter, which helps me keep the website clean.
    cookie-parser and body-parser, which both let me grab data from the users and authenticate the user.
    bcrypt, crypto, which help me hash & encrypt passwords and authenticate with passwords.
    Many more, which all helped me make this software what it is.

# Examples

![image](https://user-images.githubusercontent.com/48403821/222436084-4762325c-0dca-40a9-92c7-8c27765ab36d.png)
![image](https://user-images.githubusercontent.com/48403821/222436612-93898fa1-5097-48b9-8df2-a3f5dfcd49d9.png)
![image](https://user-images.githubusercontent.com/48403821/222436150-bfee2553-4997-49a0-a8f0-335655a2c074.png)
![image](https://user-images.githubusercontent.com/48403821/222436236-11110965-dca6-43f8-9905-72c0da5c8351.png)
![image](https://user-images.githubusercontent.com/48403821/222436271-ba01998a-2451-4425-9644-7b48ed01a5d9.png)
![image](https://user-images.githubusercontent.com/48403821/222436295-a3234a14-e017-456a-87db-e12f85b03b94.png)
![image](https://user-images.githubusercontent.com/48403821/222436694-58c4724a-e9d1-4323-920a-355a128a43b8.png)
![image](https://user-images.githubusercontent.com/48403821/222436713-dbf35cad-f21c-436a-a94d-105893bdbdf3.png)
![image](https://user-images.githubusercontent.com/48403821/222436741-373cba83-17a2-4cff-9f24-b1fe9ed038c4.png)
![image](https://user-images.githubusercontent.com/48403821/222436783-c707a767-fad4-43f4-b24a-525543984f01.png)
![image](https://user-images.githubusercontent.com/48403821/222436811-c0a2976b-10ff-48d7-b9b2-174d03d6f256.png)


# License

This program is under the MIT license. 

(c) Alex Dalas, 2023.
