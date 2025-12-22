require("dotenv").config();
const express = require("express");
const passport = require("passport");
const session = require("express-session");
const path = require("path");
const { MongoClient } = require("mongodb");
const MongoStore = require("connect-mongo");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;

const auth = express();

// MongoDB setup
const url = process.env.MONGODB_URI;
const client = new MongoClient(url);
const dbName = "user_info";
let usersCollection;

async function connectDB() {
  try {
    // Check if connected or connect
    if (!client.topology || !client.topology.isConnected()) {
      await client.connect();
    }
    usersCollection = client.db(dbName).collection("information");
    console.log("✅ MongoDB Connected (Auth)");
  } catch (err) {
    console.error("MongoDB Connection Error in Auth:", err);
  }
}
connectDB();

// Express session with MongoStore
auth.use(
  session({
    secret: process.env.SESSION_SECRET || "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: 'sessions'
    }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 1 day
  })
);

auth.use(passport.initialize());
auth.use(passport.session());

// Serialize/Deserialize
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Save user to MongoDB
async function saveUser(profile, provider) {
  if (!usersCollection) {
    await connectDB();
  }
  const existingUser = await usersCollection.findOne({
    provider_id: profile.id,
  });
  if (!existingUser) {
    await usersCollection.insertOne({
      name: profile.displayName,
      email: profile.emails?.[0]?.value || "No Email",
      provider,
      provider_id: profile.id,
      createdAt: new Date(),
    });
    console.log(`✅ New user added from ${provider}`);
  }
  return {
    id: profile.id,
    displayName: profile.displayName,
    email: profile.emails?.[0]?.value || "No Email",
  };
}

// Strategy callback wrapper
function strategyCallback(provider) {
  return async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await saveUser(profile, provider);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  };
}

// Passport Strategies

// Google
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
      },
      strategyCallback("google")
    )
  );
}

// Facebook
if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "/auth/facebook/callback",
        profileFields: ["id", "displayName", "emails"],
      },
      strategyCallback("facebook")
    )
  );
}

// GitHub
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "/auth/github/callback",
      },
      strategyCallback("github")
    )
  );
}

//  success.html

//Routes

// Google
auth.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
auth.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => res.sendFile(path.join(__dirname, "/views/share.html"))
);

// Facebook
auth.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);
auth.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  (req, res) => res.sendFile(path.join(__dirname, "/views/share.html"))
);

// GitHub
auth.get(
  "/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);
auth.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/" }),
  (req, res) => res.sendFile(path.join(__dirname, "/views/share.html")) // Fixed undefined successPath
);

module.exports = auth;
