// partial-app.js
// Purpose:
// This application includes some security improvements, but still contains
// multiple weak or incomplete configurations. It is used to evaluate whether
// the extension can distinguish between partially secure and fully insecure code.

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");

const app = express();

// Secure improvement: Helmet is enabled.
// Expected result: no Helmet warning.
app.use(helmet());

// Partially secure: express.json() is configured, but no body size limit is defined.
// Expected finding: JSON limit missing.
app.use(express.json({ strict: true }));

// Still insecure: cors() is used without restrictive origin settings.
// Expected finding: insecure CORS configuration.
app.use(cors());

// Partially secure: session cookie sets secure: true,
// but httpOnly and sameSite are still missing.
// Expected finding: insecure session cookie configuration.
app.use(
  session({
    secret: "abc123",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
    },
  })
);

// No rate limiting middleware is used.
// Expected finding: Rate limiting missing.

app.get("/dashboard", (req, res) => {
  res.send("Dashboard");
});

app.listen(3000, () => {
  console.log("Partial app running on port 3000");
});