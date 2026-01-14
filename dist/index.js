import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';

// 1️⃣ Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// 2️⃣ Middleware
app.use(cors({
  origin: '*' // Allow all frontends. Replace with your frontend URL if you want stricter CORS.
}));
app.use(express.json());

// 3️⃣ Placeholder API checks
const checkGoogleSafeBrowsing = (url) => {
  const patterns = ['paypal', 'login'];
  return patterns.some(p => url.toLowerCase().includes(p)) ? 'flagged' : 'safe';
};

const checkVirusTotal = (url) => {
  const patterns = ['secure', 'bank'];
  return patterns.some(p => url.toLowerCase().includes(p)) ? 'flagged' : 'safe';
};

const checkURLScan = (url) => {
  const patterns = ['free-', '.net'];
  return patterns.some(p => url.toLowerCase().includes(p)) ? 'flagged' : 'safe';
};

// 4️⃣ API endpoint
app.post('/api/scan', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  const reasons = [];
  if (checkGoogleSafeBrowsing(url) === 'flagged') reasons.push("Google Safe Browsing flagged this URL");
  if (checkVirusTotal(url) === 'flagged') reasons.push("VirusTotal flagged this URL");
  if (checkURLScan(url) === 'flagged') reasons.push("URLScan flagged this URL");

  const isFlagged = reasons.length > 0;

  res.json({
    flagged: isFlagged,
    reasons
  });
});

// 5️⃣ Start server
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
