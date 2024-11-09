import express from "express";
import mongoose from "mongoose";
import cors from "cors"
import route from "./routes/index.js";
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json())
app.use(express.urlencoded({ extended: true }))


// app.use(route,cors());
app.use(cors());
app.use(route);

app.get("/",(req,res)=>{
    res.json("Running");
})

app.listen(PORT,() =>{
    console.log(`Server is running on port ${PORT}`);
    console.log(`http://localhost:${PORT}`);
});