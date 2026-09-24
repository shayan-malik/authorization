import express from "express";
import cors from "cors";
import { db } from "./db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import "dotenv/config";


const app = express();
const PORT = 4000;

app.use(express.json());
app.use(cookieParser())
app.use(cors());


function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if(!authHeader){
        return res.status(401).send({status: "error", message: "No token provided"});
    }

    const token = authHeader.split(" ")[1];

    if(!token){
        return res.status(401).send({status: "error", message: "Token format invalid"});
    }

    try{
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch(error){
        console.log("error", error);
        return res.status(403).send({status: "error", message: "Invalid or expired token"});
    }

};


app.post("/signup", async (req, res) => {
    try{
        const body = req.body;
        const hashedPassword = await bcrypt.hash(body.password, 10)
    
        const response = await db.query(`INSERT INTO users (first_name, last_name, email, password_hash, phone role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`, [body.first_name, body.last_name, body.email, hashedPassword, body.phone, body.role]);

        const { password_hash, ...safeUser } = response.rows[0];

        res.send({status: "success", user: safeUser});

    }

    catch(error){
        console.log("error", error);
        res.send("Internal Server Error");
    }
});



app.post("/login", async (req, res) => {
    try{
        const {email, password} = req.body;

        const userFound = await db.query(`SELECT * FROM users WHERE email = $1`,[email]) ;
        
        if(userFound.rows.length == 0){
            return res.send({status: "error", message: "User not found"});
        }

        const user = userFound.rows[0];

        if(!user.is_active){
            return res.send({status: "error", message: "Account is inactive"});
        }

        const passwordCheck = await bcrypt.compare(password, user.password_hash);

        if(passwordCheck){
            const token = jwt.sign({ id: user.id, email: user.email}, process.env.JWT_SECRET, {expiresIn: '7d'});

            res.cookie("token", token, {
                httpOnly: true,
                secure: false,
                maxAge: 86400000
            });

            const { password_hash, ...safeUser} = user;

            res.send({status: "success", message: "Login Successfully", token, user: safeUser});

            
        }

        else{
            return res.send({status: "error", message: "Incorrect Password"});
        }

    }
    
    catch(error){
        console.log("error", error);
        res.send({status: "error", message: "Something Went Wrong"});

    }

});


app.get("/profile", verifyToken, async (req, res) => {
    try{
        const response = await db.query(`SELECT id, first_name, last_name, email, phone FROM users WHERE id = $1`, [req.user.id]);
        res.send({status: "success", user: response.rows[0]});
        
    }
    catch(error){
        console.log("error", error);
        res.send({status: "error", message: "Something went wrong"});

    }
});


app.put("/profile", verifyToken, async (req, res) => {
    try{
        const { first_name, last_name,  phone } = req.body;
        const response = await db.query(`UPDATE users SET first_name = $1, last_name = $2, phone = $3 WHERE id = $4 RETURNING *`, [first_name, last_name, phone, req.user.id]);
        res.send({status: "success", user: response.rows[0]})
    }

    catch(error){
        console.log("error", error);
        res.send({status: "error", message: "Something went wrong"});
    }

});


app.delete("/profile", verifyToken, async (req, res) => {
    try{
        const response = await db.query(`DELETE FROM users WHERE id = $1 RETURNING *`, [req.user.id]);

        if(response.rows.length === 0){
            return res.send({status: "error", message: "User not found"});
        }

        res.send({status: "success", message: "Account Deleted", user: response.rows[0]});
    }
    catch(error){
        console.log("error", error);
        res.send({status: "error", message: "Something went wrong"})
    }
});



app.listen(PORT, () => {
    console.log("Server Running on port", PORT);
});

