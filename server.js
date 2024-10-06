require("dotenv").config();
const jwt = require("jsonwebtoken");
const sanitizeHTML = require("sanitize-html");
const bcrypt = require("bcrypt"); // install bcrypt, which is used for salting and hashing user passwords so that they are NOT stored as plain-text in our database
const cookieParser = require("cookie-parser"); // necessary to read cookies, see first app.use function around line 41, which uses 'req.cookies.simpleSite' to verify user authentication by checking cookie values
const express = require("express");
const db = require("better-sqlite3")("simpleSite.db"); // creates a sqlite3 database file called 'simpleSite.db' in our project's root directory (same directory as the server.js file)
db.pragma("journal_mode = WAL"); // increases speed/efficiency of database

//! Database Setup

const createTables = db.transaction(() => {
  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL
        )`
    ).run();
    console.log("Table 'users' created successfully.");
  } catch (error) {
    console.error("Error creating table 'users':", error);
  }

  try {
    db.prepare(
      `CREATE TABLE IF NOT EXISTS posts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          createdDate TEXT,
          title TEXT NOT NULL,
          body TEXT NOT NULL,
          authorId INTEGER,
          FOREIGN KEY (authorId) REFERENCES users (id)
        )`
    ).run();
    console.log("Table 'posts' created successfully.");
  } catch (error) {
    console.error("Error creating table 'posts':", error);
  }
});

createTables();

//! End Database Setup

const app = express();

app.set("view engine", "ejs"); // npm install ejs, which is a 'template engine'
app.use(express.urlencoded({ extended: false })); // This allows us to access the request body from route handlers
app.use(express.static("public"));
app.use(cookieParser());

app.use(function (req, res, next) {
  res.locals.errors = []; // 'locals' makes something available to our template or 'views'. This makes our 'errors' array (From our /register POST route handler below) available as an empty array in the global scope before we actually reach the registration route or begin putting any errors into its errors array. This is necessary because it prevents us from throwing an "errors is not defined" error when we try to run our webpage prior to defining the 'errors' array within the local scope of the POST /register route handler.

  // try to decode incoming cookie. This is how we will verify that a user is logged in by checking that they have a cookie from simpleSite and that the value of that cookie is correct
  try {
    const decoded = jwt.verify(req.cookies.simpleSite, process.env.JWTSECRET);
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user; // allows us to access user from any ejs template
  console.log(req.user);

  next(); // remember to call next! If you do not, then this middleware will hang forever following any request made to the server.
});

//! Homepage / Dashboard

app.get("/", (req, res) => {
  // res.send("Hello World!") // send regular response directly from express server using res.send() method

  if (req.user) {
    // if the user is logged in...

      const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ?");
      const posts = postsStatement.all(req.user.userid)

      return res.render("dashboard", { posts }); // ...render the dashboard instead of the homepage
  }

  res.render("homepage"); // from homepage.ejs in the 'views' directory, rendered using ejs template engine
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/logout", (req, res) => {
  res.clearCookie("simpleSite");
  res.redirect("/");
});

//! Log In

app.post("/login", (req, res) => {
  let errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  if (req.body.username.trim() == "") errors = ["Invalid username / password"];
  if (req.body.password == "") errors = ["Invalid username / password"];

  if (errors.length) {
    return res.render("login", { errors });
  }

  const userInQuestionStatement = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  );
  const userInQuestion = userInQuestionStatement.get(req.body.username);

  if (!userInQuestion) {
    errors = ["Invalid username / password"];
    return res.render("login", { errors });
  }

  const matchOrNot = bcrypt.compareSync(
    req.body.password,
    userInQuestion.password
  );

  if (!matchOrNot) {
    errors = ["Invalid username / password"];
    return res.render("login", { errors });
  }

  // if the user input password matches the password in our database, give them a cookie

  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
      userid: userInQuestion.id,
      username: userInQuestion.username,
    },
    process.env.JWTSECRET
  ); // Here we create the token that we will use in the res.cookie method below such that the cookie we create for the user is a json web token that cannot be guessed or brute-forced by malicious users. Now if you look at the database and cookie after successfully registering a new user, you'll not only see that user and their hashed/salted password in our database but will ALSO see the cookie for 'simpleSite' with the JWT as it's 'value' in the 'application' tab of the dev tools!

  // res.cookie(a, b, c)
  // res.cookie("simpleSite", "supertopsecretvalue", {})
  res.cookie("simpleSite", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60, // 1000ms * 60s * 60m * 24h = 1 day, so the cookie will last for 1 day!
  });

  // res.send("Thank you!")
  res.redirect("/");

  // then redirect to dashboard
});

//! Create Post (after middlewares!)

function mustBeLoggedIn(req, res, next) {
  // This will redirect us to the homepage if we try to access the 'create-post' endpoint before logging in. If the user is not authenticated (There is no cookie present), the create-post route handler will redirect the user to the homepage instead.
  if (req.user) {
    return next();
  }

  return res.redirect("/");
}

app.get("/create-post", mustBeLoggedIn, (req, res) => {
  res.render("create-post");
});

function sharedPostValidation(req) {
  const errors = [];

  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";

  // trim - sanitize or strip out html
  req.body.title = sanitizeHTML(req.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  }); // removes ALL html and javascript (which could be malicious) from the post title
  req.body.body = sanitizeHTML(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  }); // removes ALL html and javascript (which could be malicious) from the post body

  if (!req.body.title) errors.push("You must provide a title");
  if (!req.body.body) errors.push("You must provide content");

  return errors;
}

app.get("/edit-post/:id", (req, res) => {
    // try to look up the post specified by post id
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = statement.get(req.params.id);

    // if you are not the author, redirect to home page
    if (post.authorid !== req.user.userid) {
        console.log(post.authorid)
        console.log(req.user.userid)
        return res.redirect("/");
    }

    // otherwise, render the edit post template
    res.render("edit-post", { post });
})

app.get("/posts/:id", (req, res) => {
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?");
    const post = statement.get(req.params.id);

    if (!post) {
        return res.redirect("/");
    }

    res.render("single-post", { post });
})

app.post("/create-post", mustBeLoggedIn, (req, res) => {
  // console.log(req.body);
  // res.send("Thank you!")

  const errors = sharedPostValidation(req);

  if (errors.length) {
    return res.render("create-post", { errors });
  }

    // if no errors, save to database

    const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)");
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString());

    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?");
    const realPost = getPostStatement.get(result.lastInsertRowid);

    res.redirect(`/posts/${realPost.id}`)
});

//! Registration

app.post("/register", (req, res) => {
  // console.log(req.body);
  const errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim(); // the .trim() method removes any whitespace at the beginning or the end of the username

  if (!req.body.username) errors.push("You must provide a username");
  if (req.body.username && req.body.username.length < 3)
    errors.push("Username must be at least 3 characters long");
  if (req.body.username && req.body.username.length > 10)
    errors.push("Username cannot exceed 10 characters");
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain letters and numbers");

  // check if username exists already
  const usernameStatement = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  );
  const usernameCheck = usernameStatement.get(req.body.username);

  if (usernameCheck) errors.push("Username is already taken");

  if (!req.body.password) errors.push("You must provide a password");
  if (req.body.password && req.body.password.length < 8)
    errors.push("Password must be at least 8 characters long");
  if (req.body.password && req.body.password.length > 20)
    errors.push("Password cannot exceed 20 characters");

  if (errors.length) {
    return res.render("homepage", { errors });
  }

  //& npm install better-sqlite3 (for database)

  //^ save the new user into a database

  const salt = bcrypt.genSaltSync(10); // generate the salt to be used for salting the user's password
  req.body.password = bcrypt.hashSync(req.body.password, salt); // replace the plain-text password with the salted and hashed password

  const statement = db.prepare(
    "INSERT INTO users (username, password) VALUES (?, ?)"
  ); // using (?, ?) allows sqlite3 to prepare this statement for us (interpolating, concatening, etc strings from user input values. This prevents users from performing SQL injections)
  const result = statement.run(req.body.username, req.body.password); //! Remember to NEVER insert user input like passwords directly into a database. Our code on lines 79 - 80 ensures that we are storing the salted/hashed version of the user's password, NOT the plain-text password itself.

  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const ourUser = lookupStatement.get(result.lastInsertRowid);

  //^ log the user in by giving them a cookie

  //   const token = jwt.sign(a, b)
  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
      userid: ourUser.id,
      username: ourUser.username,
    },
    process.env.JWTSECRET
  ); // Here we create the token that we will use in the res.cookie method below such that the cookie we create for the user is a json web token that cannot be guessed or brute-forced by malicious users. Now if you look at the database and cookie after successfully registering a new user, you'll not only see that user and their hashed/salted password in our database but will ALSO see the cookie for 'simpleSite' with the JWT as it's 'value' in the 'application' tab of the dev tools!

  // res.cookie(a, b, c)
  // res.cookie("simpleSite", "supertopsecretvalue", {})
  res.cookie("simpleSite", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60, // 1000ms * 60s * 60m * 24h = 1 day, so the cookie will last for 1 day!
  });

  // res.send("Thank you!")
  res.redirect("/");
});

const PORT = 8000;
app.listen(8000, console.log(`Server is listening on port ${PORT}`));
