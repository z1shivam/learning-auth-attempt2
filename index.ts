import express from "express";
import dotenv from "dotenv";
import path from "path";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

const webRoot = path.resolve(__dirname, "public/index.html");

app.get("/", (req, res) => {
  res.sendFile(path.resolve(webRoot));
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
