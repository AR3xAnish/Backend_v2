//2nd Approach

import dotenv from "dotenv"
import connectDB from "./db/index.js"
import { app } from "./app.js"

dotenv.config({
    path:"./.env",
    // debug:true
})

connectDB()
.then(()=>{
    app.listen(process.env.PORT||8000,()=>{
        console.log(`Server running at PORT ${process.env.PORT}`);
        
    })
})
.catch((err)=>{
    console.log("MONGODB connection failed",err);
    
})






//1st Approach

// import express from "express"
// const app =express()

// ;(async ()=>{
//     try {
//         await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
//         app.on("error",(error)=>{
//             console.log("ERR",error);
//             throw error  
//         })

//         app.listen(process.env.PORT,()=>{
//             console.log(`APP listening at port ${process.env.PORT}`)
//         })
//     } catch (error) {
//         console.log("ERROR:",error);
//     }
// })()