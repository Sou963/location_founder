require("dotenv").config();
const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
const path = require("path");
const bcrypt = require("bcryptjs");
const auth = require('./auth');
const { MongoClient } = require("mongodb");

const url = process.env.MONGODB_URI;
const client = new MongoClient(url);
const dbname = "user_info";

//middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "/views/login.html"));
});
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "/views/reg.html"));
});
app.get("/mytracker", (req, res) => {
  res.sendFile(path.join(__dirname, "/views/track.html"));
});

//register user
app.post("/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  try {
    // In serverless, we should check if connected or use a cached connection pattern
    // For now, retaining original logic but adding error handling for connection
    await client.connect();
    const db = client.db(dbname);
    const col = db.collection("information");
    const existing = await col.findOne({ email });
    if (existing) {
      return res.send("email is already existing");
    }
    else if (password !== confirmPassword) {
      return res.send("password not matching");
    }
    const hash = await bcrypt.hash(password, 10);
    const insert = await col.insertOne({ name, email, password: hash });
    if (insert) {
      res.status(200).sendFile(path.join(__dirname, "/views/login.html"));
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});
//login user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    await client.connect();
    const db = client.db(dbname);
    const col = db.collection('information');
    const user = await col.findOne({ email });

    if (!user) {
      return res.send('invalid email or password');
    }
    const ismatch = await bcrypt.compare(password, user.password);
    if (ismatch && user) {
      res.status(200).sendFile(path.join(__dirname, '/views/share.html'));
    }
    else {
      res.send('invalid email or password');
    }

  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
})

app.use('/', auth);

// Only listen if not running in Vercel (Vercel exports the app)
if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });
}

module.exports = app;
