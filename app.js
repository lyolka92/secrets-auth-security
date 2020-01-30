//jshint esversion:6

require('dotenv').config();
const express = require("express")
    , ejs = require("ejs")
    , bodyParser = require("body-parser")
    , mongoose = require("mongoose")
    , session = require("express-session")
    , passport = require("passport")
    , passportLocalMongoose = require("passport-local-mongoose")
    , GoogleStrategy = require("passport-google-oauth20").Strategy
    , FacebookStrategy = require('passport-facebook').Strategy
    , findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "OurLittleSecret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  (accessToken, refreshToken, profile, done) => {
       User.findOrCreate({googleId: profile.id},
        (err, user) => {
            return done(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  (accessToken, refreshToken, profile, done) => {
      User.findOrCreate({facebookId: profile.id}, (err, user) => {
          if (err) {
              return done(err);
            }
            done(null, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", {scope: ["https://www.googleapis.com/auth/plus.login"]})
);

app.get("/auth/facebook",
    passport.authenticate("facebook")
);

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/auth/google/secrets", 
    passport.authenticate("google", {failureRedirect: "/login"}), (req, res) => {
        res.redirect("/secrets");
});

app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", {failureRedirect: "/login"}), (req, res) => {
        res.redirect("/secrets");
});

app.get("/secrets", (req,res) => {
    if (req.isAuthenticated()) {
        User.find({"secret": {$ne: null}}, (err, foundUsers) => {
            if(err) {
                console.log(err);
            } else {
                if (foundUsers) {
                    res.render("secrets", {usersWithSecrets: foundUsers});
                }
            }
        });
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }    
});

app.post("/submit", (req, res) => {
    const theSecret = req.body.secret;

    User.findById(req.user.id, (err, foundUser) => {
        if (!err) {
            if(foundUser) {
                foundUser.secret = theSecret;
                foundUser.save(() => {
                    res.redirect("/secrets");
                })
            } else {
                console.log("User not found");                
            }
        } else {
            console.log(err);
        }
    })
})

app.get("/logout", (req,res) => {
    req.logOut();
    res.redirect("/");
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.logIn(user, err => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.listen("3000", () => {
    console.log("Server is running on port 3000.");
});