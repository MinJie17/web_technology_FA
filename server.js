const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const db = require("./db");
const multer = require("multer");
const session = require("express-session");
const cors = require("cors");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files from "public" folder
app.use(express.static(path.join(__dirname, "public")));
// Make uploads folder accessible to frontend images
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

app.use(
  session({
    secret: "qiu_secure_key_2026",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }, // 1 hour session
  }),
);

// --- Multer Storage Configuration (for Images) ---
const storage = multer.diskStorage({
  destination: "public/uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

/* LOST & FOUND DATA API ROUTES */
// Submit New Report (Lost/Found Item)
app.post("/api/reports", upload.single("image"), (req, res) => {
  // Check if user is logged in to get their ID
  if (!req.session.user) {
    return res
      .status(401)
      .json({ success: false, error: "Please log in first" });
  }

  try {
    const {
      item_type,
      title,
      category,
      location,
      lost_date,
      description,
      contact,
    } = req.body;

    const image_path = req.file ? `/uploads/${req.file.filename}` : null;

    const userId = req.session.user.id;

    const query = `
    INSERT INTO reports (item_type, title, category, location, lost_date, description, contact, image_path, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
      query,
      [
        item_type,
        title,
        category,
        location,
        lost_date,
        description,
        contact,
        image_path,
        userId,
      ],
      (err, result) => {
        if (err) {
          console.error("Database insert error:", err);
          return res
            .status(500)
            .json({ success: false, error: "Database failed to save report" });
        }
        res.json({ success: true, message: "Report saved successfully" });
      },
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// 2. Get All Items (For items.html and found.html)
app.get("/api/items", (req, res) => {
  const sql = `
    SELECT 
      id, 
      title, 
      location, 
      lost_date, 
      description, 
      contact, 
      image_path, 
      status, 
      created_at,
      CASE 
        WHEN LOWER(status) = 'claimed' THEN 'Found' 
        ELSE item_type 
      END AS item_type
    FROM reports 
    ORDER BY created_at DESC`;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Database error fetching items:", err);
      return res.status(500).json({ error: "Failed to fetch items" });
    }
    res.json(results);
  });
});

/* USER AUTHENTICATION API ROUTES */
// 1. Register User
app.post("/api/register", (req, res) => {
  const { username, email, password } = req.body;
  const strengthRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

  if (!strengthRegex.test(password)) {
    return res.status(400).json({
      success: false,
      error: "Password must be 8+ chars with letters and numbers.",
    });
  }

  // Check if email exists
  db.query(
    "SELECT * FROM user WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, error: "Database error" });
      }

      if (results.length > 0) {
        return res.status(400).json({
          success: false,
          error: "Email already registered.",
        });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
          "INSERT INTO user (username, email, password, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
          [username, email, hashedPassword],
          (insertErr) => {
            if (insertErr) {
              console.error("Insert error:", insertErr);
              return res.status(500).json({
                success: false,
                error: "Database failed to insert user",
              });
            }

            res.json({ success: true });
          },
        );
      } catch (hashErr) {
        console.error("Hashing error:", hashErr);
        res.status(500).json({ success: false, error: "Server error" });
      }
    },
  );
});

// 2. Login User
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM user WHERE email = ?";

  db.query(sql, [email], (err, results) => {
    if (err)
      return res.status(500).json({ success: false, error: "Database error" });

    // Check if the user actually exists before comparing passwords
    if (results.length === 0) {
      return res.status(401).json({ success: false, error: "User not found" });
    }

    const user = results[0];
    const isMatch = bcrypt.compareSync(password, user.password);

    if (isMatch) {
      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
      };
      res.json({ success: true, user: req.session.user });
    } else {
      res.status(401).json({ success: false, error: "Incorrect password" });
    }
  });
});

// Route to handle Password Reset
app.post("/api/forgot-password", async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !email.endsWith("@qiu.edu.my")) {
    return res.status(400).json({
      success: false,
      error: "Invalid email domain.",
    });
  }

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({
      success: false,
      error: "Password must be at least 8 characters.",
    });
  }

  try {
    // Check if user exists in MySQL
    db.query(
      "SELECT * FROM user WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Database select error:", err);
          return res.status(500).json({
            success: false,
            error: "Database error.",
          });
        }

        if (results.length === 0) {
          return res.status(404).json({
            success: false,
            error: "User not found.",
          });
        }

        try {
          // 3️⃣ Hash new password
          const hashedPassword = await bcrypt.hash(newPassword, 10);

          // 4️⃣ Update password in MySQL
          db.query(
            "UPDATE user SET password = ?, updated_at = NOW() WHERE email = ?",
            [hashedPassword, email],
            (updateErr, updateResult) => {
              if (updateErr) {
                console.error("Database update error:", updateErr);
                return res.status(500).json({
                  success: false,
                  error: "Failed to update password.",
                });
              }

              if (updateResult.affectedRows === 0) {
                return res.status(404).json({
                  success: false,
                  error: "User not found.",
                });
              }

              res.json({
                success: true,
                message: "Password updated successfully!",
              });
            },
          );
        } catch (hashErr) {
          console.error("Hashing error:", hashErr);
          res.status(500).json({
            success: false,
            error: "Error processing password.",
          });
        }
      },
    );
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({
      success: false,
      error: "Server error during password reset.",
    });
  }
});

/* DASHBOARD API ROUTES */
// 1. Get current logged-in user profile
app.get("/api/user/me", (req, res) => {
  if (req.session.user) {
    res.json({ success: true, user: req.session.user });
  } else {
    res.status(401).json({ success: false, error: "Not logged in" });
  }
});

// 2. Get reports belonging ONLY to the logged-in user
app.get("/api/user/reports", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, error: "Not logged in" });
  }

  const sql =
    "SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC";

  db.query(sql, [req.session.user.id], (err, results) => {
    if (err) {
      console.error("Error fetching user reports:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }
    res.json({ success: true, reports: results });
  });
});

// 3. Update User Profile (Settings)
app.put("/api/user/update", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, error: "Not logged in" });
  }

  const { username, currentPassword, newPassword } = req.body;
  const userId = req.session.user.id;

  if (newPassword) {
    if (!currentPassword) {
      return res
        .status(400)
        .json({ success: false, error: "Current password is required." });
    }

    db.query(
      "SELECT password FROM user WHERE id = ?",
      [userId],
      async (err, results) => {
        if (err) {
          console.error("Select DB Error:", err);
          return res
            .status(500)
            .json({ success: false, error: "Database error finding user" });
        }
        if (results.length === 0)
          return res
            .status(404)
            .json({ success: false, error: "User not found" });

        try {
          const dbHashedPassword = results[0].password;
          const isMatch = await bcrypt.compare(
            currentPassword,
            dbHashedPassword,
          );
          if (!isMatch) {
            return res
              .status(400)
              .json({ success: false, error: "Incorrect current password." });
          }

          const newHashedPw = await bcrypt.hash(newPassword, 10);
          const sql =
            "UPDATE user SET username = ?, password = ?, updated_at = NOW() WHERE id = ?";

          db.query(sql, [username, newHashedPw, userId], (updateErr) => {
            if (updateErr) {
              console.error("Update DB Error (Password):", updateErr.message);
              return res.status(500).json({
                success: false,
                error: "Database failed to save changes.",
              });
            }
            req.session.user.username = username;
            return res.json({
              success: true,
              message: "Password changed successfully!",
            });
          });
        } catch (catchErr) {
          console.error("Server processing error:", catchErr);
          return res
            .status(500)
            .json({ success: false, error: "Server processing error" });
        }
      },
    );
  } else {
    const sql = "UPDATE user SET username = ?, updated_at = NOW() WHERE id = ?";

    db.query(sql, [username, userId], (err) => {
      if (err) {
        console.error("Update DB Error (Username):", err.message);
        return res
          .status(500)
          .json({ success: false, error: "Database failed to save username." });
      }
      req.session.user.username = username;
      return res.json({
        success: true,
        message: "Username updated successfully!",
      });
    });
  }
});

// 4. Logout
app.get("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

/* UPDATE & DELETE ROUTES (For Dashboard) */
// Edit an existing report
app.put("/api/reports/:id", (req, res) => {
  const reportId = req.params.id;
  const { title, location, status, description } = req.body;

  const sql = `UPDATE reports SET title = ?, location = ?, status = ?, description = ? WHERE id = ?`;

  db.query(sql, [title, location, status, description, reportId], (err) => {
    if (err) {
      console.error("Error updating report:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }
    res.json({ success: true });
  });
});

// Delete a report
app.delete("/api/reports/:id", (req, res) => {
  const reportId = req.params.id;

  db.query("DELETE FROM reports WHERE id = ?", [reportId], (err) => {
    if (err) {
      console.error("Error deleting report:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }
    res.json({ success: true });
  });
});

// Update ONLY the status (when clicking "Mark Claimed")
app.put("/api/reports/:id/status", (req, res) => {
  const reportId = req.params.id;
  const { status } = req.body;

  if (!req.session.user) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  const sql = "UPDATE reports SET status = ? WHERE id = ?";
  db.query(sql, [status, reportId], (err, result) => {
    if (err) {
      console.error("Database error updating status:", err);
      return res.status(500).json({ success: false, error: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ success: false, error: "Report not found" });
    }

    res.json({ success: true, message: "Status updated successfully" });
  });
});

/* SERVER START */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
