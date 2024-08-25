const express = require("express")
const router = express.Router();
const authcontrollers = require("../controllers/auth-controller")
const signupSchema = require("../validators/auth.validator");
const validate = require("../middleware/validate-middleware");
const authMiddleware = require("../middleware/auth-middleware");
const { updatePassword } = require("../controllers/auth-controller");

router.route('/').get(authcontrollers.home);
router.route('/register').post(validate(signupSchema), authcontrollers.register);
router.route('/login').post(authcontrollers.login);
router.route('/me').get(authMiddleware, authcontrollers.getUserData);
router.route("/update-password").post (authMiddleware, updatePassword);
router.route('/logout').post(authMiddleware, authcontrollers.logout);
router.route("/forgot-password").post( authcontrollers.forgotPassword);
router.route("/reset-password/:token").post( authcontrollers.resetPassword);


module.exports = router;