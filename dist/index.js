import dotenv from 'dotenv';
// 1. Load environment variables at the very top
dotenv.config();
import express from 'express';
import cors from 'cors';
const app = express();
const PORT = process.env.PORT || 0; // 0 = auto-assign free port
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
// 6. Enable CORS for the frontend origin
app.use(cors({
    origin: 'http://localhost:5173'
}));
app.use(express.json());
// 3. Placeholder API Checks
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
// 2. API Endpoint
app.post('/api/scan', (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: "URL is required" });
    }
    const reasons = [];
    // Run the three simulated services
    if (checkGoogleSafeBrowsing(url) === 'flagged')
        reasons.push("Google Safe Browsing flagged this URL");
    if (checkVirusTotal(url) === 'flagged')
        reasons.push("VirusTotal flagged this URL");
    if (checkURLScan(url) === 'flagged')
        reasons.push("URLScan flagged this URL");
    // 4. Logic: If ANY API result is 'flagged' → overall is flagged
    const isFlagged = reasons.length > 0;
    // 5. Response Shape (STRICT)
    res.json({
        flagged: isFlagged,
        reasons: reasons
    });
});
app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});
