import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import session from "express-session";
import fileUpload from "express-fileupload";

// const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet());

app.get("/", (req, res) => {
  res.send("Hello");
});

app.use(express.json());

app.listen(3000);


