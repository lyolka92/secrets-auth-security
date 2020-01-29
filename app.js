//jshint esversion:6

require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const md5 = require("md5");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema);

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {
    const newUser = new User({
        email: req.body.username,
        password: md5(req.body.password)
    });

    newUser.save(err => {
        if (!err) {
            res.render("secrets");
        } else {
            res.send(err)
        }
    });
});

app.post("/login", (req, res) => {
    const userPassword = md5(req.body.password);

    User.findOne(
        {email: req.body.username},
        (err, foundUser) => {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    if (foundUser.password === userPassword) {
                        res.render("secrets");
                    } else {
                        res.send("Your password is incorrect.");
                    }   
                } else {
                    res.send("User is not found.");
                }
            }
        });
});




app.listen("3000", () => {
    console.log("Server is running on port 3000.");
});