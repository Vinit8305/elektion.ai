const User = require("../models/user-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer"); // Add this line to send emails
const crypto = require("crypto"); // Add this line to generate tokens

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
            return res.status(400).json({ message: "email is already exists" })
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

const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const userExist = await User.findOne({ email });

        if (!userExist) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const isPasswordCorrect = await bcrypt.compare(password, userExist.password);

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // Check the user type
        if (userExist.usertype === 'surveyor') {
            res.status(200).json({
                msg: "Login success",
                token: await userExist.generateToken(),
                userId: userExist._id.toString(),
                redirect: "/surveyor"  // Redirect URL for surveyor
            });
        } else if (userExist.usertype === 'politicalworker') {
            res.status(200).json({
                msg: "Login success",
                token: await userExist.generateToken(),
                userId: userExist._id.toString(),
                redirect: "/politicalworker"  // Redirect URL for politicalworker
            });
        } else {
            res.status(400).json({ message: "Invalid user type" });
        }
    } catch (error) {
        next(error);
    }
}


// Get logged-in user's data //

const getUserData = async (req, res) => {
    try { 
        const userId = req.user.userId;

        const user = await User.findById(userId).select("-password");

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(user); 
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};

// update password //

const updatePassword = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { currentPassword, newPassword, confirmNewPassword } = req.body;

        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ message: "New password and confirmation do not match" });
        }

        const user = await User.findById(userId);

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Current password is incorrect" });
        }

        if (newPassword.length < 5) {
            return res.status(400).json({ message: "New password must be at least 5 characters long" });
        }

        // Hash the new password before saving
        const salt = await bcrypt.genSalt(10);
         user.password = await newPassword;

        await user.save();

        res.status(200).json({ message: "Password updated successfully" });
    } catch (error) {
        console.error("Error updating password:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};

const logout = async (req, res) => {
    try {
        // Here, you can optionally perform any server-side session cleanup if necessary.
        res.status(200).json({ message: "Logout successful",token: "" });
        
    } catch (error) {
        console.error("Error during logout:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Generate a reset token and set expiry time
        const resetToken = crypto.randomBytes(32).toString("hex");
        user.resetToken = resetToken;
        user.resetTokenExpiry = Date.now() + 3600000; // Token valid for 1 hour
        await user.save();

        // Create transporter for sending email
        const transporter = nodemailer.createTransport({
            service: "Gmail", 
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        // Define the reset link and send the email
        const resetLink = `http://localhost:5004/api/auth/reset-password/${resetToken}`;
        await transporter.sendMail({
            to: email,
            subject: "Password Reset Request",
            html: `<p>You requested a password reset. Click the link below to reset your password:</p>
                   <a href="${resetLink}">${resetLink}</a>`,
        });

        res.status(200).json({ message: "Password reset link sent to your email" });
    } catch (error) {
        console.error("Error in forgotPassword:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};

const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { newPassword, confirmNewPassword } = req.body;

    try {
        // Find the user with the valid reset token and check if it hasn't expired
        const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token" });
        }

        // Ensure the passwords match
        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        user.password = await newPassword;
        // Clear the reset token and expiry
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();

        res.status(200).json({ message: "Password reset successfully" });
    } catch (error) {
        console.error("Error in resetPassword:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};


module.exports = { home, register, login, getUserData, updatePassword, logout, forgotPassword, resetPassword };


