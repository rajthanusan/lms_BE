const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

dotenv.config(); // Load environment variables from .env file

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MySQL database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || "", // Default to an empty string if no password is provided
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    return;
  }
  console.log("Connected to the database.");
});

const encryptPassword = async (password) => {
  // Hash the password using bcrypt
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

const comparePassword = async (password, hashedPassword) => {
  // Compare the password with the hashed password
  return await bcrypt.compare(password, hashedPassword);
};

app.post("/api/employeeregister", async (req, res) => {
  const {
    username,
    password,
    name,
    department,
    handphone,
    birthday,
    joindate,
  } = req.body;

  // Validate required fields
  if (!username || !password || !name || !handphone) {
    return res
      .status(400)
      .send("Username, password, name, and contact are required");
  }

  try {
    // Hash the password
    const hashedPassword = await encryptPassword(password);

    // Set the role to 'employee' by default
    const role = "employee";

    // Insert user into the database with the role 'employee'
    db.query(
      "INSERT INTO users (username, password, role, name, department, handphone, birthday, joindate) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        username,
        hashedPassword,
        role, // Always set as 'employee'
        name,
        department || null, // Use NULL if department is not provided
        handphone || null,
        birthday || null, // Use NULL if birthday is not provided
        joindate || null, // Use NULL if joindate is not provided
      ],
      (err, result) => {
        if (err) {
          console.error("Registration failed:", err);
          return res.status(500).send("Registration failed");
        }
        res.status(201).send({ message: "Registration successful" });
      }
    );
  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).send("Server error");
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  // Input validation
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    // Query to find the user in the database
    db.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, result) => {
        if (err) {
          console.error("Login failed:", err);
          return res
            .status(500)
            .json({ message: "Login failed due to server error" });
        }

        // Check if user exists
        if (result.length > 0) {
          const user = result[0];

          // Compare the input password with the hashed password in the database
          const match = await comparePassword(password, user.password);

          if (match) {
            // Successful login
            return res.json({
              message: "Login successful",
              userData: {
                username: user.username,
                role: user.role,
                name: user.name,
                additionalData: {
                  department: user.department || null,
                  contact: user.contact || null,
                },
              },
            });
          } else {
            // Invalid password
            return res
              .status(401)
              .json({ message: "Invalid username or password" });
          }
        } else {
          // No user found
          return res
            .status(401)
            .json({ message: "Invalid username or password" });
        }
      }
    );
  } catch (error) {
    console.error("Login failed:", error);
    return res
      .status(500)
      .json({ message: "Login failed due to server error" });
  }
});

app.post("/api/crmanager", async (req, res) => {
  const {
    username,
    password,
    name,
    department,
    landline,
    handphone,
    birthday,
    joindate,
  } = req.body;

  // Validate required fields
  if (!username || !password || !name || !handphone) {
    return res
      .status(400)
      .send("Username, password, name, and handphone are required");
  }

  try {
    // Hash the password
    const hashedPassword = await encryptPassword(password);

    // Set the role to 'manager'
    const role = "manager";

    // Insert user into the database with the role 'manager'
    db.query(
      "INSERT INTO users (username, password, role, name, department, landline, handphone, birthday, joindate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        username,
        hashedPassword,
        role, // Set as 'manager'
        name,
        department || null, // Use NULL if department is not provided
        landline || null, // Insert landline (null if not provided)
        handphone || null, // Insert handphone (null if not provided)
        birthday || null, // Use NULL if birthday is not provided
        joindate || null, // Use NULL if joindate is not provided
      ],
      (err, result) => {
        if (err) {
          console.error("Registration failed:", err);
          // Check for specific database errors if needed
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).send("Username already exists");
          }
          return res.status(500).send("Registration failed");
        }
        // Successfully created manager
        return res
          .status(201)
          .send({ message: "Manager has been added successfully" });
      }
    );
  } catch (error) {
    console.error("Error hashing password:", error);
    return res.status(500).send("Server error");
  }
});

app.get("/api/users", (req, res) => {
  db.query("SELECT * FROM users", (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).send("Error : Failed to fetch users");
    }
    res.status(200).send(results);
  });
});

app.post("/api/Leaveapply", (req, res) => {
  const { leave, startdate, enddate, comments, username, status } = req.body;

  const query =
    "INSERT INTO leave_applications (leave_type, start_date, end_date, comments, username, status) VALUES (?, ?, ?, ?, ?, ?)";
  db.query(
    query,
    [leave, startdate, enddate, comments, username, status],
    (err, result) => {
      if (err) {
        console.error("Database error:", err); // Log the actual error
        return res.status(500).send("Error saving leave application");
      }
      res.status(201).send("Leave application saved successfully");
    }
  );
});

app.get("/api/LeaveView/", (req, res) => {
  db.query("SELECT * FROM leave_applications", (err, result) => {
    if (err) {
      console.error("Failed to load leave applications:", err);
      return res
        .status(500)
        .json({ error: "Failed to load leave applications" });
    }
    // Check if there are results
    if (result.length === 0) {
      return res.status(404).json({ message: "No leave applications found" });
    }
    res.status(200).json({ data: result });
  });
});
// Route to get leave types

app.get("/api/Manager", (req, res) => {
  const sql = 'SELECT * FROM users where role="manager"'; // Adjust based on your table name
  db.query(sql, (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json(result);
  });
});

app.get("/api/Manager/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM users WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json(result[0]);
  });
});

app.put("/api/Manager/:id", async (req, res) => {
  const { id } = req.params;
  const {
    username,
    password,
    name,
    department,
    landline,
    handphone,
    birthday,
    joindate,
  } = req.body;

  // Validate required fields
  if (!username || !name || !handphone) {
    return res.status(400).send("Username, name, and handphone are required");
  }

  try {
    // Hash the new password if provided
    const hashedPassword = password
      ? await encryptPassword(password)
      : undefined;

    // Prepare the SQL update query
    const sql = `
      UPDATE users 
      SET 
        username = ?, 
        ${hashedPassword ? "password = ?," : ""}
        name = ?, 
        department = ?, 
        landline = ?, 
        handphone = ?, 
        birthday = ?, 
        joindate = ?
      WHERE id = ?
    `;

    // Prepare the parameters for the query
    const params = [
      username,
      ...(hashedPassword ? [hashedPassword] : []), // Only add hashedPassword if it exists
      name,
      department || null,
      landline || null,
      handphone || null,
      birthday || null,
      joindate || null,
      id,
    ].filter((param) => param !== undefined); // Filter out any undefined parameters

    // Execute the update query
    db.query(sql, params, (err, result) => {
      if (err) {
        console.error("Update failed:", err);
        return res.status(500).send("Update failed");
      }
      if (result.affectedRows === 0) {
        return res.status(404).send("Manager not found");
      }
      return res.status(200).send({ message: "Manager updated successfully" });
    });
  } catch (error) {
    console.error("Error hashing password:", error);
    return res.status(500).send("Server error");
  }
});

// Delete a manager
app.delete("/api/Manager/:id", (req, res) => {
  const { id } = req.params;
  const sql = "DELETE FROM users WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: "Manager deleted successfully" });
  });
});

app.put("/api/LeaveView/:id", (req, res) => {
  console.log("Request received:", req.params, req.body); // Add this line for debugging
  const { id } = req.params;
  const { leave_type, start_date, end_date, comments, username, status } =
    req.body;

  const query = `
      UPDATE leave_applications 
      SET leave_type = ?, start_date = ?, end_date = ?, comments = ?, username = ?, status = ? 
      WHERE id = ?
  `;

  db.query(
    query,
    [leave_type, start_date, end_date, comments, username, status, id],
    (err, result) => {
      if (err) {
        //console.error('Failed to update leave application:', err);
        return res.status(500).send("Failed to update leave application");
      }
      if (result.affectedRows === 0) {
        return res.status(404).send("Leave application not found");
      }
      res.send({ message: "Leave application updated successfully" });
    }
  );
});

// Endpoint for deleting a student
app.delete("/api/LeaveView/delete/:id", (req, res) => {
  const { id } = req.params;

  db.query(
    "DELETE FROM leave_applications WHERE id = ?",
    [id],
    (err, result) => {
      if (err) {
        console.error("Failed to delete employee:", err);
        return res.status(500).send("Failed to delete employee");
      }
      res.send({ message: "employee deleted successfully" });
    }
  );
});

// Route to get employees based on department
// Route to get employees based on department

app.delete("/api/User/delete/:id", (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM users WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Failed to delete employee:", err);
      return res.status(500).send("Failed to delete employee");
    }
    res.send({ message: "employee deleted successfully" });
  });
});

// Create a new leave type

// Get all leave types
app.get("/api/getLeavetype", (req, res) => {
  // Assuming your leave_types table has columns 'leave_type_name' and 'total_days'
  db.query("SELECT leave_type_name, days FROM leave_types", (err, result) => {
    if (err) {
      console.error("Failed to load leave types:", err);
      return res.status(500).json({ error: "Failed to load leave types" });
    }
    // Check if there are results
    if (result.length === 0) {
      return res.status(404).json({ message: "No leave types found" });
    }
    // Map result to ensure it has the expected structure
    const leaveTypes = result.map((item) => ({
      leave_type_name: item.leave_type_name,
      total_days: item.days || 0, // Default to 0 if total_days is undefined
    }));
    res.status(200).json(leaveTypes); // Return the formatted leave types
  });
});

// Get leave type by ID

// Update a leave type
app.post("/api/Leavetype", (req, res) => {
  const { leave_type_name, days } = req.body; // Change 'leave' to 'leave_type_name'
  const query = "INSERT INTO leave_types (leave_type_name, days) VALUES (?, ?)";
  db.query(query, [leave_type_name, days], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Failed to add leave type" });
    }
    res
      .status(201)
      .json({ message: "Leave type added successfully", data: result });
  });
});

// Get all leave types
app.get("/api/Leavetype", (req, res) => {
  db.query("SELECT * FROM leave_types", (err, result) => {
    if (err) {
      console.error("Failed to load leave types:", err);
      return res.status(500).json({ error: "Failed to load leave types" });
    }
    // Check if there are results
    if (result.length === 0) {
      return res.status(404).json({ message: "No leave types found" });
    }
    res.status(200).json(result); // Assuming result is an array of leave types
  });
});

// Get leave type by ID

// Update a leave type
app.put("/api/Leavetype/:id", (req, res) => {
  console.log("Request received:", req.params, req.body); // Debug the request

  const { id } = req.params;
  const { leave_type_name, days } = req.body; // Ensure these match the request body

  const query = `
      UPDATE leave_types 
      SET leave_type_name = ?, days = ?
      WHERE id = ?
  `;

  db.query(query, [leave_type_name, days, id], (err, result) => {
    if (err) {
      console.error("Failed to update leave application:", err); // Log detailed error
      return res.status(500).send("Failed to update leave application");
    }
    if (result.affectedRows === 0) {
      return res.status(404).send("Leave application not found");
    }
    res.send({ message: "Leave application updated successfully" });
  });
});

// Delete a leave type
app.delete("/api/Leavetype/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM leave_types WHERE id = ?";
  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Failed to delete leave type" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Leave type not found" });
    }
    res.json({ message: "Leave type deleted successfully" });
  });
});

app.get("/api/Leavetype/:id", (req, res) => {
  const { id } = req.params;
  const sql = "SELECT * FROM leave_types WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json(result[0]);
  });
});

app.get("/api/AllDepartment", (req, res) => {
  const sql = "SELECT * FROM department"; // Retrieve distinct departments
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.json(results.map((row) => row.department_name)); // Send department names
  });
});

/*
app.get('/api/Department', (req, res) => {
    const sql = 'SELECT * FROM manager';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});*/

/// Get all departments
app.get("/api/Department", (req, res) => {
  const sql = "SELECT * FROM department"; // Adjusted to select from the correct table
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching departments:", err);
      return res.status(500).send("Error fetching departments");
    }
    res.json(results);
  });
});

// Get department by ID
app.get("/api/Department/:id", (req, res) => {
  const sql = "SELECT * FROM department WHERE id = ?"; // Adjusted to select from the correct table
  db.query(sql, [req.params.id], (err, result) => {
    if (err) {
      console.error("Error fetching department by ID:", err);
      return res.status(500).send("Error fetching department");
    }
    if (result.length === 0) {
      return res.status(404).send("Department not found");
    }
    res.json(result[0]);
  });
});

// Create a new department
app.post("/api/department", async (req, res) => {
  const { department_name, location } = req.body;

  // Validate required fields
  if (!department_name || !location) {
    return res.status(400).send("All fields are required");
  }

  try {
    // Insert department into the database
    const sql =
      "INSERT INTO department (department_name, location) VALUES (?, ?)";
    db.query(sql, [department_name, location], (err, result) => {
      if (err) {
        console.error("Department creation failed:", err);
        return res.status(500).send("Department creation failed");
      }
      res.status(201).json({ id: result.insertId, department_name, location });
    });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).send("Server error");
  }
});

// Update a department by ID
app.put("/api/department/:id", (req, res) => {
  const { department_name, location } = req.body; // Removed manager_email and manager_password

  // Validate required fields
  if (!department_name || !location) {
    return res.status(400).send("All fields are required");
  }

  const sql =
    "UPDATE department SET department_name = ?, location = ? WHERE id = ?"; // Adjusted to update the correct table and fields
  db.query(sql, [department_name, location, req.params.id], (err, result) => {
    if (err) {
      console.error("Error updating department:", err);
      return res.status(500).send("Error updating department");
    }
    if (result.affectedRows === 0) {
      return res.status(404).send("Department not found");
    }
    res.json({ message: "Department updated successfully" });
  });
});

// Delete a department by ID
app.delete("/api/Department/:id", (req, res) => {
  const sql = "DELETE FROM department WHERE id = ?"; // Adjusted to delete from the correct table
  db.query(sql, [req.params.id], (err, result) => {
    if (err) {
      console.error("Error deleting department:", err);
      return res.status(500).send("Error deleting department");
    }
    if (result.affectedRows === 0) {
      return res.status(404).send("Department not found");
    }
    res.json({ message: "Department deleted successfully" });
  });
});

app.get("/find-department", (req, res) => {
  const username = req.query.username;
  const sql = "SELECT department FROM users WHERE username = ?";

  db.query(sql, [username], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (results.length > 0) {
      res.json({ department: results[0].department });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  });
});

app.get("/api/User", (req, res) => {
  const { department } = req.query; // Get department from query parameters

  if (!department) {
    return res.status(400).json({ error: "Department not provided" });
  }

  db.query(
    'SELECT * FROM users WHERE department = ? and role="employee" ',
    [department],
    (err, result) => {
      if (err) {
        console.error("Failed to load employees:", err);
        return res.status(500).json({ error: "Failed to load employees" });
      }

      if (result.length === 0) {
        return res
          .status(404)
          .json({ message: "No employees found for this department" });
      }

      res.status(200).json(result); // Send back the filtered employee data
    }
  );
});

app.get("/api/LeaveApply/", (req, res) => {
  const { department } = req.query; // Get department from query parameters

  if (!department) {
    return res.status(400).json({ error: "Department not provided" });
  }

  // First, get all employees from the specified department
  db.query(
    "SELECT username FROM users WHERE department = ?",
    [department],
    (err, employeeResult) => {
      if (err) {
        console.error("Failed to load employees:", err);
        return res.status(500).json({ error: "Failed to load employees" });
      }

      if (employeeResult.length === 0) {
        return res
          .status(404)
          .json({ message: "No employees found for this department" });
      }

      // Extract the usernames of employees in the department
      const usernames = employeeResult.map((emp) => emp.username);

      if (usernames.length === 0) {
        return res
          .status(404)
          .json({ message: "No leave applications found for this department" });
      }

      // Now, fetch the leave applications for the employees in that department
      db.query(
        "SELECT * FROM leave_applications WHERE username IN (?)",
        [usernames],
        (err, leaveResult) => {
          if (err) {
            console.error("Failed to load leave applications:", err);
            return res
              .status(500)
              .json({ error: "Failed to load leave applications" });
          }

          if (leaveResult.length === 0) {
            return res.status(404).json({
              message: "No leave applications found for this department",
            });
          }

          // Return the leave applications for the department
          res.status(200).json({ data: leaveResult });
        }
      );
    }
  );
});

const generateResetToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

const sendEmail = async (to, subject, text) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "Gmail", // Fetch service from env
      auth: {
        user: "rajthanusan08@gmail.com", // Fetch email user from env
        pass: "gjfi fuas wekw lmwd", // Fetch email password from env
      },
    });

    const mailOptions = {
      from: "thanusanraj49@gmail.com", // Fetch sender email from env
      to,
      subject,
      text,
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error("Error sending email:", error);
    throw error; // Ensure errors are propagated
  }
};

app.post("/api/request-password-reset", (req, res) => {
  const { email } = req.body;
  const code = crypto.randomBytes(6).toString("hex");
  const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

  // Update query
  const query =
    "UPDATE users SET reset_code = ?, reset_code_expiry = ? WHERE username = ?";

  db.query(query, [code, expiry, email], async (error, results) => {
    if (error) {
      console.error("Error processing request:", error);
      return res
        .status(500)
        .json({ success: false, message: "Error processing request" });
    }

    if (results.affectedRows > 0) {
      try {
        await sendEmail(
          email,
          "Password Reset Request - Leave Management System",
          `Dear User,
          
          We have received a request to reset your password for your Leave Management System account.
          
          Your password reset code is: **${code}**.
          
          You can use the following link to log in with your updated password: [Login to Leave Management System](https://lms-model.netlify.app/login).
          
          If you did not request a password reset, please disregard this email. If you have any concerns, feel free to contact our support team.
          
          Thank you,  
          Leave Management System Team
          
          **Note:** This code will expire in 30 minutes.
          `
        );
        res.json({ success: true });
      } catch (emailError) {
        console.error("Error sending email:", emailError);
        res
          .status(500)
          .json({ success: false, message: "Error sending email" });
      }
    } else {
      res.status(404).json({ success: false, message: "Username not found" });
    }
  });
});

app.post("/api/verify-code", (req, res) => {
  const { email, code } = req.body;

  db.query(
    "SELECT * FROM users WHERE username = ? AND reset_code = ? AND reset_code_expiry > NOW()",
    [email, code],
    (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ success: false, message: "Database error" });

      if (results.length > 0) {
        res.json({ success: true });
      } else {
        res
          .status(400)
          .json({ success: false, message: "Invalid or expired code" });
      }
    }
  );
});
app.post("/api/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const hashedPassword = await encryptPassword(newPassword);

    db.query(
      "UPDATE users SET password = ?, reset_code = NULL, reset_code_expiry = NULL WHERE username = ?",
      [hashedPassword, email],
      (err, results) => {
        if (err)
          return res
            .status(500)
            .json({ success: false, message: "Database error" });

        if (results.affectedRows > 0) {
          res.json({ success: true });
        } else {
          res
            .status(400)
            .json({ success: false, message: "Error resetting password" });
        }
      }
    );
  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.put("/api/LeaveApply/:id/:action", (req, res) => {
  const { id, action } = req.params;
  const validActions = ["approved", "rejected"];

  console.log(`Received request to ${action} leave request with ID ${id}`);

  if (!validActions.includes(action)) {
    return res.status(400).json({ error: "Invalid action" });
  }

  // First query: Update leave request status
  db.query(
    "UPDATE leave_applications SET status = ? WHERE id = ?",
    [action, id],
    (error, results) => {
      if (error) {
        console.error("Database update failed:", error); // Log error for debugging
        return res.status(500).json({ error: "Database update failed" });
      }

      console.log("Query results:", results); // Log results for debugging
      if (results.affectedRows === 0) {
        return res.status(404).json({ error: "Leave request not found" });
      }

      // If the update was successful, execute the second query
      // Second query: Fetch the user's email
      db.query(
        "SELECT username AS email FROM users WHERE username = (SELECT username FROM leave_applications WHERE id = ?)",
        [id],
        async (error, results) => {
          if (error) {
            console.error("Error fetching email:", error); // Log error for debugging
            return res.status(500).json({ error: "Error fetching email" });
          }

          if (results.length === 0) {
            return res.status(404).json({ error: "User not found" });
          }

          const employeeEmail = results[0].email; // Assuming username is the email
          const subject = `Leave Request ${action.charAt(0).toUpperCase() + action.slice(1)}`;

          const text = `Dear User,

We would like to inform you that the status of your leave request has been updated.
          
Your leave request has been APPROVED. You can check the status by using the following link: https://lms-model.netlify.app/myleave.
          
If you have any questions or need further assistance, please do not hesitate to contact us.
          
Thank you,  
The Leave Management System Team`;
          



          

          // Send email
          try {
            await sendEmail(employeeEmail, subject, text);
            res.json({
              message: "Leave request updated successfully and email sent",
            });
          } catch (emailError) {
            console.error("Error sending email:", emailError);
            res.status(500).json({
              error: "Leave request updated, but failed to send email",
            });
          }
        }
      );
    }
  );
});

const port = process.env.PORT || 8085; // Use the PORT from the environment or default to 8085 locally
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
