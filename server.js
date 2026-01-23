import express from "express"; // server framework
import cors from "cors"; // allows frontend to talk to backend
import dotenv from "dotenv"; // keeps environment variables credentials secure
import validator from "validator"; // validates emails
import rateLimit from "express-rate-limit";
import { logEvent } from "./utils/logger.js";
import { pool } from "./db/postgres.js";
import { Resend } from "resend";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// Rate limiter
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                   // max 5 requests per IP
  handler: (req, res) => {
    logEvent("RATE_LIMITED", {
      ip: req.ip,
    });

    res.status(429).json({
      error: "Too many requests. Please try again later.",
    });
  },
});

// POST CONTACT ROUTE
app.post("/api/contact", contactLimiter, async (req, res) => {
  const {firstName, lastName, email, subject, message, company } = req.body;

  // log spam (honeypot trigger)
  if (company) {
    logEvent("SPAM_BLOCKED", {
      ip: req.ip,
    });
    return res.status(200).json({ success: true });
  }

  if (!firstName || !lastName || !email || !message) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  // HEAVY email validation using validator.js
  if (!email || !validator.isEmail(email)) {
    return res.status(400).json({
      error: "Please provide a valid email address"
    });
  }

  // Email length validation
  if (!validator.isLength(email, { max: 254 })) {
    return res.status(400).json({
      error: "Email address is too long"
    });
  }

  // Message length validation
  if (!message || message.length > 1000) {
    return res.status(400).json({
      error: "Message must be less than 1000 characters"
    });
  }

  // Prevents obvious XSS - basic sanitization
  const sanitizedMessage = validator.escape(message);
  const sanitizedFirstName = validator.escape(firstName);
  const sanitizedLastName = validator.escape(lastName);
  const sanitizedSubject = validator.escape(subject);

  try {
    const { data, error } = await resend.emails.send({
      from: 'Portfolio Contact <onboarding@resend.dev>',
      to: [process.env.EMAIL_USER],
      reply_to: email,
      subject: sanitizedSubject || "New Portfolio Contact",
      text: `Name: ${sanitizedFirstName} ${sanitizedLastName}\nEmail: ${email}\nSubject: ${sanitizedSubject}\nMessage: ${sanitizedMessage}`,
      html: `
        <h3>New Contact Form Submission</h3>
        <p><strong>Name:</strong> ${sanitizedFirstName} ${sanitizedLastName}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Subject:</strong> ${sanitizedSubject || 'None'}</p>
        <p><strong>Message:</strong></p>
        <p>${sanitizedMessage}</p>
      `
    });

    await pool.query(
      `
      INSERT INTO messages
      (first_name, last_name, email, subject, message, ip_address)
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [
        firstName,
        lastName,
        email,
        subject || null,
        message,
        req.ip,
      ]
    );

    logEvent("SUCCESS", {
      ip: req.ip,
      email,
      subject,
    });

    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Server error:", error);

    logEvent("ERROR", {
      ip: req.ip,
      error: error.message,
    });

    res.status(500).json({ error: "Failed to send message. Please try again later." });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Handle Pool Shutdown - Resource-awareness
process.on("SIGINT", async () => {
  await pool.end();
  process.exit(0);
});
