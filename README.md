# simple-login

This was a school project, which served as a simple posting system.

It allows for users to post and comment on anyones post, while admins can ban, delete, or edit user's profiles or posts.

This app is a demonstration of how you can create an application with tokens and authentication, and should only be used as an example or reference.

If you don't really care about that, and want to take to code, just know that it should only really be used in trusted environments, unless you audit the security of the app yourself (remember, a school project)

# Setup

Serve public_html using the platform of your choice (Apache, Nginx, python3 http.server, etc)

Download all of the code, run 'npm install', and then run the main.js file (with npm run start). 

Edit all of the HTML files to point the HTML to your main.js

You might have to make a "cert.crt" and "pk.key" file in the root of the directory, these will serve as a HTTP certificate and Private Key.

You now have the code set up. The rest is up to you.

# Lisence

This program is under the MIT license. 

(c) Alex Dalas, 2023.
