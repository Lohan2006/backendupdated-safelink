import express from "express";
import cors from "cors";
import dotenv from "dotenv";

import scanRoute from "./routes/scan.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.use("/api/scan", scanRoute);

const PORT = process.env.PORT || 5000;

// Starts the backend server.
// Makes the API available for incoming scan requests.
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
