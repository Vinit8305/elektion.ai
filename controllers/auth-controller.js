const User = require("../models/user-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const home = async (req, res) => {
    try {
        res.status(200).send("controller is perfectly working");
    } catch (error) {
        console.log(error);
    }
}

// user Registration  //

const register = async (req, res) => {
    try {
        const { username, email, phone, password, usertype } = req.body;
        const userExist = await User.findOne({ email: email })
        if (userExist) {
            return res.status(400).json({ message: "email.is already exists" })
        }
        const userCreated = await User.create({
            username,
            email,
            phone,
            password,
            usertype,
        });
        res.status(201).json({
            msg: "registration success",
            token: await userCreated.generateToken(),
            userId: userCreated._id.toString()
        });
    } catch (error) {
        res.status(500).send("internal server error");

    }
}

// ---user Login--- //

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const userExist = await User.findOne({ email });

        if (!userExist) {
            return res.status(400).json({ message: "invaild credentials" });
        }
        const user = await bcrypt.compare(password, userExist.password);
        if (user) {
            res.status(200).json({
                msg: "login success",
                token: await userExist.generateToken(),
                userId: userExist._id.toString()
            });
        } else {
            res.status(401).json({ message: "invalid email or password" })
        }
    } catch (error) {
        next(error);
    }
}
module.exports = { home, register, login };