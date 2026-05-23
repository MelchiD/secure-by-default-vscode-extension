const express = require("express");
const cors = require("cors");
const session = require("express-session");
const multer = require("multer");

const app = express();
app.use(cors(
  
)); // insecure
app.use(express.json()); // no limit


app.use(
  session({
    secret: "1234",
    resave: true,
    saveUninitialized: true,
    cookie: {
      secure: false,
      httpOnly: false,
    },
  })
);

app.listen(3000);



// Safer session config for mine that is being flagged by semgrep

// app.use( 
//   session({ 
//     secret: process.env.SESSION_SECRET, 
//     resave: false, 
//     saveUninitialized: false, 
//     store: {}, // placeholder so your current rule does not flag missing store 
//     cookie: {
//        secure: true, 
//        httpOnly: true, 
//        sameSite: "lax", 
//     },
//  })
// );