require("dotenv").config();
const express = require("express");

const app = express();
const router = require("./router/auth-router")
const connectDB = require("./utils/db");
const errorMiddleware = require("./middleware/error-middleware");
const adminRoute = require("./router/admin-router")

app.use(express.json());

app.use("/api/auth", router)
app.use("/api/admin",adminRoute)

app.use(errorMiddleware)

const PORT = 5004;

connectDB().then(()=>{
app.listen(PORT,()=>{
    console.log(`server is runing on prot ${PORT}`);
    
    })
})