const express = require("express");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const dbPath = path.join(__dirname, "todo.db");

let db = null;

const initializeDBAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });

        app.listen(5000, () => {
            console.log("Server Running at http://localhost:5000/");
        });
    } catch (e) {
        console.log(`DB Error: ${e.message}`);
        process.exit(1);
    }
};

initializeDBAndServer();

// Middleware to verify JWT
const authenticateJWT = (request, response, next) => {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return response.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (error, user) => {
        if (error) return response.sendStatus(403);
        request.user = user;
        next();
    });
};

// User Registration
app.post("/register", async (request, response) => {
    const { id, username, password, role } = request.body;
    const hashedPassword = await bcrypt.hash(password, 8);

    try {
        const dbUser = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
        if (dbUser) {
            response.status(400).send("User already exists");
        } else {
            await db.run(`INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)`, [id, username, hashedPassword, role]);
            response.send("User created successfully");
        }
    } catch (error) {
        response.status(500).send("Error registering user");
    }
});

// User Login
app.post("/login", async (request, response) => {
    const { username, password } = request.body;
    try {
        const dbUser = await db.get(`SELECT * FROM users WHERE username = ?`, [username]);
        if (dbUser && await bcrypt.compare(password, dbUser.password)) {
            const token = jwt.sign({ id: dbUser.id, role: dbUser.role }, process.env.JWT_SECRET);
            response.json({ token });
        } else {
            response.status(400).send("Invalid username or password");
        }
    } catch (error) {
        response.status(500).send("Error logging in");
    }
});

// Create To-Do
app.post("/todos", authenticateJWT, async (request, response) => {
    const { id, task, isCompleted } = request.body;
    const userId = request.user.id;

    try {
        await db.run(`INSERT INTO todos (id, user_id, task, is_completed) VALUES (?, ?, ?, ?)`, [id, userId, task, isCompleted]);
        response.send("To-Do created successfully");
    } catch (error) {
        response.status(500).send("Error creating To-Do");
    }
});

// Get All To-Dos
app.get("/todos", authenticateJWT, async (request, response) => {
    const userId = request.user.id;

    try {
        const todos = await db.all(`SELECT * FROM todos WHERE user_id = ?`, [userId]);
        response.send(todos);
    } catch (error) {
        response.status(500).send("Error retrieving To-Dos");
    }
});

// Update To-Do
app.put("/todos/:id", authenticateJWT, async (request, response) => {
    const { id } = request.params;
    const { task, isCompleted } = request.body;

    try {
        await db.run(`UPDATE todos SET task = ?, is_completed = ? WHERE id = ?`, [task, isCompleted, id]);
        response.send("To-Do updated successfully");
    } catch (error) {
        response.status(500).send("Error updating To-Do");
    }
});

// Delete To-Do
app.delete("/todos/:id", authenticateJWT, async (request, response) => {
    const { id } = request.params;

    try {
        await db.run(`DELETE FROM todos WHERE id = ?`, [id]);
        response.send("To-Do deleted successfully");
    } catch (error) {
        response.status(500).send("Error deleting To-Do");
    }
});
