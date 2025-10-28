// server.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";

// Routes
import authRoutes from "./routes/authRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";

// Middleware
import { errorHandler } from "./middleware/errorHandler.js";

// Load .env variables
dotenv.config();

const app = express();

// 🔹 Middleware
app.use(helmet());
app.use(compression());
app.use(cors({ origin: process.env.FRONTEND_URL || "*", credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🔹 Logging
app.use(morgan("tiny"));

// 🔹 Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
});
app.use(limiter);

// 🔹 Health Check
app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "success",
    message: "Egerton SmartSphere Backend is running on Vercel",
    time: new Date().toISOString(),
  });
});

// 🔹 API Routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);

// 🔹 404
app.use("*", (req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// 🔹 Error handler
app.use(errorHandler);

// ✅ Export Express app for Vercel (don’t use app.listen)
export default app;
