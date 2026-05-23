const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const session = require("express-session");
const multer = require("multer");
const rateLimit = require("express-rate-limit");

const app = express();

// Disable Express fingerprinting
app.disable("x-powered-by");

// Safer security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
    },
  })
);

// Safer JSON body limit
app.use(express.json({ limit: "10kb" }));

// Safer CORS policy
app.use(
  cors({
    origin: "https://example.com",
    credentials: true,
  })
);

// Safer trust proxy setting
app.set("trust proxy", 1);

// Example rate limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
});



// Safer session config for semgrep and mine
app.use(
  session({
    name: "__Host.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: {},
    cookie: {
      domain: "example.com",
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      expires: new Date(Date.now() + 15 * 60 * 1000),
    },
  })
);

// Safer static path
app.use(express.static("public"));

// Safer upload config
const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});


// Avoid user-controlled redirect
app.get("/go", (req, res) => {
  res.redirect("/dashboard");
});

// Auth route with visible rate limiting nearby
app.post("/login", authLimiter, (req, res) => {
  res.send("Login route protected");
});

app.post("/upload", upload.single("file"), (req, res) => {
  res.send("Uploaded");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});