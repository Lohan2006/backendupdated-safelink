import express from "express";
import fetch from "node-fetch";
import dns from "dns/promises";
import { URL } from "url";

const router = express.Router();

/* ---------------- GOOGLE SAFE BROWSING ---------------- */
async function googleSafeBrowsing(url) {
  try {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "safe-link", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );

    const data = await res.json();
    return {
      checked: true,
      status: data.matches ? "malicious" : "clean",
      details: data.matches ? "Threat detected" : "No threats found"
    };
  } catch (err) {
    console.error("Google Safe Browsing error:", err);
    return { checked: false, status: "error", details: "Google API failed" };
  }
}

/* ---------------- VIRUSTOTAL ---------------- */
async function virusTotal(url) {
  try {
    const apiKey = process.env.VIRUSTOTAL_KEY;

    // Submit URL for scanning
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });
    const submitData = await submitRes.json();
    const analysisId = submitData.data?.id;
    if (!analysisId)
      return { checked: true, status: "error", details: "Failed to submit URL" };

    // Poll until analysis is complete
    let analysisData;
    const maxAttempts = 20;  // increase max attempts for slow scans
    let attempt = 0;
    while (attempt < maxAttempts) {
      const analysisRes = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { method: "GET", headers: { "x-apikey": apiKey } }
      );
      analysisData = await analysisRes.json();

      if (analysisData.data?.attributes?.status === "completed") break;

      // Wait 5 seconds before next attempt
      await new Promise((r) => setTimeout(r, 5000));
      attempt++;
    }

    if (analysisData.data?.attributes?.status !== "completed") {
      return {
        checked: true,
        status: "error",
        details: "Analysis still pending after multiple attempts",
      };
    }

    // Parse results
    const engines = analysisData.data.attributes.results || {};
    let maliciousCount = 0,
      suspiciousCount = 0;
    const totalEngines = Object.keys(engines).length;

    for (const engine of Object.values(engines)) {
      if (engine.category === "malicious") maliciousCount++;
      else if (engine.category === "suspicious") suspiciousCount++;
    }

    let status;
    if (maliciousCount > 0) status = "malicious";
    else if (suspiciousCount > 0) status = "suspicious";
    else status = "clean";

    return {
      checked: true,
      status,
      details: `VirusTotal: ${maliciousCount} malicious, ${suspiciousCount} suspicious out of ${totalEngines} engines`,
    };
  } catch (err) {
    console.error("VirusTotal error:", err);
    return { checked: false, status: "error", details: "VirusTotal API failed" };
  }
}

/* ---------------- ABUSEIPDB ---------------- */
async function abuseIPDB(url) {
  try {
    const apiKey = process.env.ABUSEIPDB_KEY;
    const hostname = new URL(url).hostname;
    const { address } = await dns.lookup(hostname);

    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${address}`,
      {
        headers: {
          Key: apiKey,
          Accept: "application/json"
        }
      }
    );

    const data = await res.json();
    const score = data.data?.abuseConfidenceScore ?? 0;

    return {
      checked: true,
      status: score > 30 ? "suspicious" : "clean",
      details: `Abuse score: ${score}%`
    };
  } catch (err) {
    console.error("AbuseIPDB error:", err);
    return { checked: false, status: "error", details: "AbuseIPDB API failed" };
  }
}

/* ---------------- MAIN ROUTE ---------------- */
router.post("/", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  try {
    const [google, vt, abuse] = await Promise.all([
      googleSafeBrowsing(url),
      virusTotal(url),   
      abuseIPDB(url)
    ]);

    let verdict = "clean";
    if (google.status === "malicious" || vt.status === "malicious") verdict = "malicious";
    else if (abuse.status === "suspicious" || vt.status === "suspicious") verdict = "suspicious";

    res.json({
      finalVerdict: verdict,
      summary: "External API scan completed",
      checks: { googleSafeBrowsing: google, virusTotal: vt, abuseIPDB: abuse }
    });
  } catch (err) {
    console.error("Scan route error:", err);
    res.status(500).json({ error: "External scan failed" });
  }
});

export default router;
