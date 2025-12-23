require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const { MongoClient } = require("mongodb");
const auth = require("./auth");

const app = express();
const port = process.env.PORT || 3000;
console.log("🔥 Server file started...");
const uri = process.env.MONGODB_URI;

if (!uri) {
  console.error("❌ ERROR: MONGODB_URI is missing in .env file!");
  process.exit(1);
}

let cachedClient = null;

async function getDB() {
  if (!cachedClient) {
    try {
      console.log("⏳ Connecting to MongoDB...");
      const client = new MongoClient(uri);
      cachedClient = await client.connect();
      console.log("✅ MongoDB Connected Successfully");
    } catch (err) {
      console.error("❌ MongoDB Connection Failed:", err);
      throw err;
    }
  }
  return cachedClient.db("user_info");
}

/*******************************
 * MIDDLEWARE
 *******************************/
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static files
app.use(express.static(path.join(__dirname, "public")));

/*******************************
 * PAGES
 *******************************/
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views/login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "views/reg.html"));
});

app.get("/mytracker", (req, res) => {
  res.sendFile(path.join(__dirname, "views/track.html"));
});

/*******************************
 * REGISTER ROUTE
 *******************************/
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password) {
      return res.send("All fields required");
    }

    if (password !== confirmPassword) {
      return res.send("Password not matching");
    }

    const db = await getDB();
    const users = db.collection("information");

    const existing = await users.findOne({ email });
    if (existing) {
      return res.send("Email already exists");
    }

    const hash = await bcrypt.hash(password, 10);
    await users.insertOne({ name, email, password: hash });

    res.sendFile(path.join(__dirname, "views/login.html"));
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).send("Internal Server Error");
  }
});

/*******************************
 * LOGIN ROUTE
 *******************************/
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const db = await getDB();
    const users = db.collection("information");

    const user = await users.findOne({ email });
    if (!user) return res.send("Invalid email or password");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send("Invalid email or password");

    res.sendFile(path.join(__dirname, "views/share.html"));
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).send("Internal Server Error");
  }
});

/*******************************
 * SOCIAL AUTH ROUTES
 *******************************/
app.use(auth);

/*******************************
 * START SERVER
 *******************************/
// app.listen(port, () => {
//   console.log(`🚀 Server running on http://localhost:${port}`);
// });

module.exports = app;
