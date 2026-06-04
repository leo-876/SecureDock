const express = require("express");
const serialize = require("node-serialize");
const lodash = require("lodash");
const axios = require("axios");

const app = express();
app.use(express.json());

// CVE-2017-5941: node-serialize RCE vulnerability
app.post("/deserialize", (req, res) => {
  const data = req.body.data;
  const obj = serialize.unserialize(data); // dangerous: allows RCE via IIFE
  res.json({ result: obj });
});

// CVE-2019-10744: lodash prototype pollution
app.post("/merge", (req, res) => {
  const target = {};
  lodash.defaultsDeep(target, req.body); // vulnerable to prototype pollution
  res.json(target);
});

// CVE-2023-45857: axios CSRF token leak (old version)
app.get("/fetch", async (req, res) => {
  const url = req.query.url;
  const response = await axios.get(url);
  res.json(response.data);
});

// Hardcoded secrets (CWE-798) — detected by Snyk as misconfiguration
const DB_PASSWORD = "supersecret123";
const API_KEY = "sk-prod-abc123xyz456";

app.get("/health", (req, res) => {
  res.json({ status: "ok", version: "1.0.0" });
});

app.listen(3000, () => {
  console.log("target-app listening on port 3000");
});
