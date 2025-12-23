const express = require("express");
const passport = require("passport");
const path = require("path");
const { MongoClient } = require("mongodb");

const GoogleStrategy = require("passport-google-oauth20").Strategy;
// const GitHubStrategy = require("passport-github2").Strategy; // Comment out if not using GitHub

const auth = express();

// ===== MongoDB cached connection =====
const uri = process.env.MONGODB_URI;
let cachedClient = null;

async function getDB() {
  if (!cachedClient) {
    const client = new MongoClient(uri);
    cachedClient = await client.connect();
    console.log("✅ MongoDB Connected (auth)");
  }
  return cachedClient.db("user_info");
}

// ===== Passport init (NO session) =====
auth.use(passport.initialize());

// ===== Google OAuth =====
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback", // Use absolute URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const db = await getDB();
        const col = db.collection("information");

        const exists = await col.findOne({
          provider: "google",
          provider_id: profile.id,
        });

        if (!exists) {
          await col.insertOne({
            name: profile.displayName,
            email: profile.emails?.[0]?.value || "No Email",
            provider: "google",
            provider_id: profile.id,
            createdAt: new Date(),
          });
        }

        done(null, profile);
      } catch (err) {
        done(err);
      }
    }
  )
);

// ===== GitHub OAuth ===== (Comment out entire block if not using; otherwise, fill .env with valid creds)
/*
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/github/callback", // Use absolute URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const db = await getDB();
        const col = db.collection("information");

        const exists = await col.findOne({
          provider: "github",
          provider_id: profile.id,
        });

        if (!exists) {
          await col.insertOne({
            name: profile.displayName,
            email: profile.emails?.[0]?.value || "No Email",
            provider: "github",
            provider_id: profile.id,
            createdAt: new Date(),
          });
        }

        done(null, profile);
      } catch (err) {
        done(err);
      }
    }
  )
);
*/

// ===== Routes =====
auth.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

auth.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    res.sendFile(path.join(__dirname, "views/share.html"));
  }
);

// Comment out if not using GitHub
/*
auth.get("/auth/github", passport.authenticate("github"));

auth.get(
  "/auth/github/callback",
  passport.authenticate("github", { session: false }),
  (req, res) => {
    res.sendFile(path.join(__dirname, "../views/share.html"));
  }
);
*/

module.exports = auth;
