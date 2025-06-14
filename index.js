import express from "express"
import bodyParser from "body-parser"
import pg from "pg"
import bcrypt from "bcrypt"
import session from "express-session"
import passport from "passport"
import { Strategy } from "passport-local"
import GoogleStrategy from "passport-google-oauth2"
import GitHubStrategy from "passport-github2"
import FacebookStrategy from "passport-facebook"
import dotenv from "dotenv"
import jwt from 'jsonwebtoken';
import cookieParser from "cookie-parser"

const app = express()
const port = 3000
const saltRounds = 10
dotenv.config();

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static("public"))
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000,
  }
}))

app.use(passport.initialize());
app.use(passport.session())
app.use(cookieParser())

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
})
db.connect()

app.get("/", (req,res) => {
  res.render("Home.ejs");
})

app.get("/register", (req, res) => {
  res.render("Register.ejs", {userTaken: false})
})

app.get("/login", (req, res) => {
  res.render("Login.ejs")
})

app.get(
  "/auth/google",
  passport.authenticate("google", { // here we previously had local 
    scope: ["profile", "email"],
  })
)

app.get("/auth/google/testing", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}))

app.get(
  "/auth/github",
  passport.authenticate("github", { // here we previously had local 
    scope: ["user:email"],
  })
)

app.get(
  "/auth/github/testing",
  passport.authenticate("github", { failureRedirect: "/login" }), // First, authenticate
  (req, res) => { // Then, handle the response
    console.log(req.user);
    const token = jwt.sign({ id: req.user.id }, process.env.SESSION_SECRET);
    res.cookie("token", token);
    res.redirect("/");
  }
);


app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { // here we previously had local 
    scope: ["email"],
  })
)

app.get("/auth/facebook/testing", 
  passport.authenticate("facebook", { failureRedirect: "/login" }), 
    (req, res) => {
      console.log(req.user)
      const token = jwt.sign({ id: req.user.id }, process.env.SESSION_SECRET)
      res.cookie("token", token)
      res.redirect("/");
    }
  )

app.get("/testing", (req, res) => {
  try {
  const data = jwt.verify(req.cookies.token, process.env.SESSION_SECRET)
  console.log(data)
  if(data.id)
    res.send(data.id.toString())
  else
    res.render("home.ejs")
  }
  catch (err) {
    console.log(err)
    res.redirect("/login")
  }
})

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err)
      return next(err)
    res.clearCookie("token") //remove JWT Token
    req.session.destroy(() => {
      res.redirect("/login");
    })
  })
})

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
      if (err) {
          return next(err); // Handle server errors
      }
      if (!user) {
          return res.redirect("/login"); // Redirect on failure
      }
      
      req.logIn(user, (err) => {
          if (err) {
              return next(err);
          }
        console.log(req.user);
        const token = jwt.sign({ id: req.user.id }, process.env.SESSION_SECRET)
        res.cookie("token", token)
        return res.redirect("/"); // Redirect on success
      });
  })(req, res, next);
})

passport.use(new Strategy(async function verify(username, password, cb) {
  try {
    const result = await db.query("select * from sphere where email = $1", [username])
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const pass = user.password

      bcrypt.compare(password, pass, (err, result) => {
        if (err) {
          return cb(err)
        } else {
          if (result) {
            return cb(null, user)
          } else {
            return cb(null, false)
          }
        }
      })
    } else 
        return cb("User not found")
  } catch (err) {
    return cb(err)
  }
}))

app.post("/register", async (req, res) => {
  const email = req.body.username
  const password = req.body.password

  const resultCheck = await db.query("select * from sphere where email = $1", [email])

  try {
    if (resultCheck.rows.length > 0) {
      return res.render("Register.ejs", {userTaken: true})
      // return res.status(409).json({ message: "Username already taken" }); // 409 Conflict
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error Hashing pass: ",err)
        } else {
          console.log("Hashed Password: ", hash)
          const result = await db.query("insert into sphere (email, password) values($1, $2) returning *"
            , [email, hash]
          )
          const user = result.rows[0]
          req.login(user, (err) => {
            console.log(err)
            console.log(user);
            const token = jwt.sign({ id: user.id }, process.env.SESSION_SECRET)
            res.cookie("token", token)
            res.redirect("/")
          })
        }
      })
    }
  } catch (err) {
    console.log(err)
  }
})

passport.use("google", 
  new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/testing",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  }, async (accessToken, refreshToken, profile, cb) => {
    try {
      const result = await db.query("select * from sphere where email = $1", [profile.email])

      if (result.rows.length === 0) {
        const newUser = await db.query("insert into users (email, password) values ($1, $2)  returning *", [profile.email, "goooglelele"])
        return cb(null, newUser.rows[0])
      } else {
        return cb(null, result.rows[0])
      }
    } catch (err) {
      return cb(err)
    }
  })
)

passport.use("github", 
  new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/testing",
    scope: ['user:email']
  }, async (accessToken, refreshToken, profile, cb) => {
    // callback function which gets triggered when a user succeeds in login
    //refreshToken just helps the remain signed in as we go along 
    try {
      console.log(profile)
      const email = profile._json.login
      if (!email) return cb(new Error("No email found in Facebook profile"))

      const result = await db.query("select * from sphere where email = $1", [email])


      if (result.rows.length === 0) {
        const newUser = await db.query("insert into sphere (email, password) values ($1, $2)  returning *", [email, "GitHub"])
        return cb(null, newUser.rows[0]) // we add newUser so that when we serialize and deserialize the user we can then access it in the same location when we goto the secrets
      } else {
        return cb(null, result.rows[0]) // Never forget to return cb 
      }
    } catch (err) {
      return cb(err)
    }
  } ) 
)

passport.use("facebook", 
  new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/testing",
  }, async (accessToken, refreshToken, profile, cb) => {
    // callback function which gets triggered when a user succeeds in login
    //refreshToken just helps the remain signed in as we go along 
    try {
      console.log(profile)
      const email = profile._json.name;
      if (!email) return cb(new Error("No email found in Facebook profile"))

      const result = await db.query("select * from sphere where email = $1", [email])


      if (result.rows.length === 0) {
        const newUser = await db.query("insert into sphere (email, password) values ($1, $2) returning *", [email, "facebook"])
        console.log(newUser)
        return cb(null, newUser.rows[0]) // we add newUser so that when we serialize and deserialize the user we can then access it in the same location when we goto the secrets
      } else {
        return cb(null, result.rows[0]) // Never forget to return cb 
      }
    } catch (err) {
      return cb(err)
    }
  } ) 
)

passport.serializeUser((user, cb) => {
  cb(null, user)
})

passport.deserializeUser((user, cb) => {
  cb(null, user)
})

app.listen(port, () => {
  console.log("App listening at port 3000");
  
})