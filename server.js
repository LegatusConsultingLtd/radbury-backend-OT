const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 4000;
const SECRET = process.env.SECRET || "radbury_secret_key";


// Middleware
app.use(cors());
app.use(bodyParser.json());

// Database init
const db = new sqlite3.Database("./database.sqlite", async (err) => {
  if (err) console.error("Error opening DB:", err);
  else {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
      )
    `);
    db.run(`
      CREATE TABLE IF NOT EXISTS overtime (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        date TEXT,
        hours REAL,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    // Seed default admin
    db.get(
      `SELECT * FROM users WHERE email = ?`,
      ["md@radbury.com"],
      async (err, row) => {
        if (!row) {
          const hashedPassword = await bcrypt.hash("password123", 10);
          db.run(
            `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
            ["md@radbury.com", hashedPassword, "admin"],
            function (err) {
              if (err)
                console.error("Error seeding admin:", err.message);
              else
                console.log(
                  "✅ Default admin created: md@radbury.com / password123"
                );
            }
          );
        }
      }
    );
  }
});

// Auth middleware
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Register (normal staff)
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
    [email, hashedPassword, "user"],
    function (err) {
      if (err) return res.status(400).json({ error: "User exists" });
      res.json({ success: true });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
      if (!user) return res.status(400).json({ error: "Invalid credentials" });
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(400).json({ error: "Invalid credentials" });

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        SECRET,
        { expiresIn: "1d" }
      );
      res.json({ token, role: user.role });
    }
  );
});

// Add overtime (normalize date)
app.post("/overtime", authenticateToken, (req, res) => {
  const { date, hours } = req.body;

  // Force ISO YYYY-MM-DD format
  const formattedDate = new Date(date).toISOString().split("T")[0];

  db.run(
    `INSERT INTO overtime (user_id, date, hours) VALUES (?, ?, ?)`,
    [req.user.id, formattedDate, hours],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Get user overtime (with optional filtering)
app.get("/overtime", authenticateToken, (req, res) => {
  const { startDate, endDate } = req.query;
  let query = `SELECT id, date, hours FROM overtime WHERE user_id = ?`;
  const params = [req.user.id];

  if (startDate && endDate) {
    query += ` AND date BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Update overtime (normalize date too)
app.put("/overtime/:id", authenticateToken, (req, res) => {
  const { date, hours } = req.body;
  const { id } = req.params;

  const formattedDate = new Date(date).toISOString().split("T")[0];

  db.run(
    `UPDATE overtime SET date = ?, hours = ? WHERE id = ? AND user_id = ?`,
    [formattedDate, hours, id, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0)
        return res.status(404).json({ error: "Not found" });
      res.json({ success: true });
    }
  );
});

// Delete overtime (user only deletes own entries)
app.delete("/overtime/:id", authenticateToken, (req, res) => {
  const { id } = req.params;

  db.run(
    `DELETE FROM overtime WHERE id = ? AND user_id = ?`,
    [id, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0)
        return res.status(404).json({ error: "Not found" });
      res.json({ success: true });
    }
  );
});

// Admin view overtime with optional date range
app.get("/admin/overtime", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);

  const { startDate, endDate } = req.query;
  let query = `
    SELECT o.id, u.email, o.date, o.hours 
    FROM overtime o 
    JOIN users u ON o.user_id = u.id
  `;
  const params = [];

  if (startDate && endDate) {
    query += ` WHERE o.date BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }

  console.log("📌 Running SQL:", query, "with params:", params);

  db.all(query, params, (err, rows) => {
    if (err) {
      console.error("❌ SQL error:", err.message);
      return res.status(500).json({ error: err.message });
    }
    console.log("✅ Query returned:", rows.length, "rows");
    res.json(rows);
  });
});

// 🚨 TEMPORARY ROUTE TO PROMOTE USERS TO ADMIN
app.post("/make-admin", (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: "Email required" });

  db.run(
    `UPDATE users SET role = 'admin' WHERE email = ?`,
    [email],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0)
        return res.status(404).json({ error: "User not found" });

      res.json({ success: true, message: `${email} is now an admin ✅` });
    }
  );
});

app.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
});
