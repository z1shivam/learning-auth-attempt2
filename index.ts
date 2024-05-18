import express from "express";
import dotenv from "dotenv";
import path from "path";
import mongoose, { ConnectOptions } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const mongoConnect = async () => {
  const connnectionInstance = await mongoose.connect(
    `${process.env.MONGO_URL!}/${process.env.MONGO_DB!}`,
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    } as ConnectOptions
  );
  console.log(`MongoDB connected: ${connnectionInstance.connection.host}`);
};
mongoConnect();

const userSchema = new mongoose.Schema(
  {
    name: {
      first_name: {
        type: String,
        required: true,
      },
      last_name: {
        type: String,
      },
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

const webRoot = path.resolve(__dirname, "public/index.html");

app.get("/", (req, res) => {
  res.sendFile(path.resolve(webRoot));
});

app.post("/register", async (req, res) => {
  const { first_name, last_name, email, password, username } = req.body;
  if (!first_name || !email || !password || !username) {
    return res.status(400).json({ message: "All fields are required" });
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  try {
    const user = new User({
      name: {
        first_name: req.body.first_name,
        last_name: req.body.last_name,
      },
      email: req.body.email,
      password: hashedPassword,
      username: req.body.username,
    });
    const newUser = await user.save();
    res.json(newUser);
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

app.post("/login", async (req, res) => {
  if (!req.body.username || !req.body.password) {
    return res.status(400).json({ message: "All fields are required" });
  }
  const cookie = req.cookies["auth-token"];
  if (cookie) {
    return res.status(400).json({ message: "User already logged in" });
  }  
  try {
    const user = await User.findOne({
      username: req.body.username,
    });
    if (user) {
      const validPassword = await bcrypt.compare(
        req.body.password,
        user.password
      );
      if (validPassword) {
        const payload = {
          user: {
            id: user.id,
          },
        };
        const token = jwt.sign(payload, process.env.JWT_SECRET!, {
          expiresIn: "1h",
        });
        res.cookie("auth-token", token).json({ token });
      } else {
        res.status(400).json({ message: "Invalid password" });
      }
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error: any) {
    res.status(400).json({ message: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
