
const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

const SECRET = "MY_SUPER_SECRET";

const db = mysql.createPool({
    host: "containers-us-west-mysql.railway.internal.railway.app",
    user: "root",
    password: "BuMqsXsdbiSMyGskuERjKENRSKbKDGdJ",
    database: "railway",
    port: 3306,
    waitForConnections: true,
    connectionLimit: 10
});

app.get("/create-user", async (req, res) => {
try{
    const password = await bcrypt.hash("123456", 10);

    await db.query(
        `INSERT INTO staff 
        (employee_code, name, email, phone, department, role, shift_type, password_hash) 
        VALUES (?,?,?,?,?,?,?,?)`,
        [
            "EMP001",
            "John Doe",
            "john@test.com",
            "9876543210",
            "ICU",
            "Doctor",
            "Morning",
            password
        ]
    );

    res.send("Staff Created");

 } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});
app.post("/login", async (req, res) => {

    try{

        const { phone, password, device_id } = req.body;

        const [rows] = await db.query(
            "SELECT * FROM staff WHERE phone=? AND is_active=TRUE",
            [phone]
        );

        if (!rows.length)
            return res.status(401).send("User not found");

        const user = rows[0];

        const valid = await bcrypt.compare(password, user.password_hash);

        if (!valid)
            return res.status(401).send("Invalid password");

        // Device binding
        if (user.device_id && user.device_id !== device_id)
            return res.status(403).send("Device not allowed");

        if (!user.device_id) {
            await db.query(
                "UPDATE staff SET device_id=? WHERE id=?",
                [device_id, user.id]
            );
        }

        const token = jwt.sign(
            { id: user.id, role: user.role },
            SECRET,
            { expiresIn: "8h" }
        );

        res.json({ token });

    }catch(err){
        console.log(err);
        res.status(500).send("Server Error");
    }

});


app.get("/generate-qr", async (req, res) => {

    const timestamp = Date.now().toString();

    const token = crypto
        .createHmac("sha256", SECRET)
        .update(timestamp)
        .digest("hex");

    const code = Math.floor(100000 + Math.random() * 900000); // 6 digit code

    const expires = new Date(Date.now() + 60000); // valid 60 sec

    await db.query(
        "INSERT INTO qr_sessions (token, expires_at) VALUES (?,?)",
        [token, expires]
    );

    res.json({
        token: token,
        code: code
    });
});

app.get("/attendance-report", async (req, res) => {

    const [rows] = await db.query(`
        SELECT 
        staff.name AS staff_name,
        staff.phone,
        staff.shift_type AS shift,
        attendance.check_time,
        attendance.type,
        attendance.method
        FROM attendance
        JOIN staff 
        ON attendance.staff_id = staff.id
        ORDER BY attendance.check_time DESC
    `);

    res.json(rows);

});

app.post("/scan", async (req, res) => {

    const { token, type } = req.body; 
    const auth = req.headers.authorization;

    if (!auth)
        return res.status(401).send("No auth");

    const decoded = jwt.verify(auth.split(" ")[1], SECRET);

    const [qr] = await db.query(
        "SELECT * FROM qr_sessions WHERE token=? AND expires_at > NOW()",
        [token]
    );

    if (!qr.length)
        return res.status(400).send("Invalid or expired QR");

    // Prevent double ENTRY within 5 minutes
    const [last] = await db.query(
        "SELECT * FROM attendance WHERE staff_id=? ORDER BY check_time DESC LIMIT 1",
        [decoded.id]
    );

    if (last.length) {
        const diff = (Date.now() - new Date(last[0].check_time)) / 60000;
        if (diff < 5)
            return res.status(400).send("Already marked recently");
    }

    await db.query(
        `INSERT INTO attendance (staff_id, type, method) 
         VALUES (?, ?, 'QR')`,
        [decoded.id, type]   // type = ENTRY or EXIT
    );

    // Delete token (prevent screenshot reuse)
    await db.query(
        "DELETE FROM qr_sessions WHERE token=?",
        [token]
    );

    res.send("Attendance Recorded");
});

app.post("/attendance-code", async (req, res) => {

    const { code } = req.body;
    const auth = req.headers.authorization;

    if (!auth)
        return res.status(401).send("Login required");

    const decoded = jwt.verify(auth.split(" ")[1], SECRET);

    // Check if QR session exists (valid code window)
    const [qr] = await db.query(
        "SELECT * FROM qr_sessions WHERE expires_at > NOW() ORDER BY id DESC LIMIT 1"
    );

    if (!qr.length)
        return res.status(400).send("Code expired");

    // record attendance
    await db.query(
        "INSERT INTO attendance (staff_id, type, method) VALUES (?, 'ENTRY', 'CODE')",
        [decoded.id]
    );

    res.send("Attendance Recorded using Code");

});




/**app.listen(5000, "0.0.0.0", () => {
  console.log("Server running on port 5000");
});**/



 const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});
