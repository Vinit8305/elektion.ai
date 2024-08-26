const express = require("express");
const getAllUsers = require("../controllers/admin-controller")
const router = express.Router();

router.route("/Users").get(getAllUsers);

module.exports = router;