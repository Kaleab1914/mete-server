const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const serviceAccount = require("./firebase-service-account.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
const port = 3000;

require("dotenv").config();
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;


app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ---------------- MongoDB ----------------
// mongoose
//   .connect("mongodb://127.0.0.1:27017/weather_app", {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//   })
//   .then(() => console.log("✅ Connected to MongoDB"))
//   .catch((err) => console.error("❌ MongoDB connection error:", err));


const connectDB = async () => {
  try {
    await mongoose.connect("mongodb://127.0.0.1:27017/weather_app", {
      // Optional: Add timeout settings
      serverSelectionTimeoutMS: 5000,
    });
    console.log("✅ Connected to MongoDB");
    
    // Listen for connection events
    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
    });
    
  } catch (error) {
    console.error("❌ MongoDB connection failed:", error.message);
    process.exit(1); // Exit process with failure
  }
};

// Call the function to connect
connectDB();

// ---------------- Schemas ----------------
const feedbackSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});
const Feedback = mongoose.model("Feedback", feedbackSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "viewer", "uploader"], required: true },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);


const deviceTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  city: { type: String, default: "Addis Ababa" }, 
  createdAt: { type: Date, default: Date.now },
});

const DeviceToken = mongoose.model("DeviceToken", deviceTokenSchema);

// ---------------- CSV Upload ----------------
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
const lastFilePath = path.join(uploadDir, "last.csv");




// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, "last.csv"); // Always overwrite the same file
  },
});
const upload = multer({
  storage: storage,
  fileFilter: function (req, file, cb) {
    if (path.extname(file.originalname) !== ".csv") {
      return cb(new Error("Only CSV files are allowed"));
    }
    cb(null, true);
  },
});

let weatherData = [];

// Parse CSV manually
function parseCSV(content) {
  const lines = content.split("\n").map((line) => line.trim()).filter(Boolean);
  const header = lines[0].split(",").map((h) => h.trim());
  const rows = lines.slice(1);
  const data = rows.map((row) => {
    const cols = row.split(",").map((c) => c.trim());
    const city = cols[0];
    const forecast = [];
    for (let i = 1; i < cols.length; i += 3) {
      forecast.push({
        minTemp: Number(cols[i]),
        maxTemp: Number(cols[i + 1]),
        condition: cols[i + 2],
      });
    }
    return { city, forecast };
  });
  return data;
}

// Load CSV on server start
function loadLastCSV() {
  if (fs.existsSync(lastFilePath)) {
    try {
      const fileContent = fs.readFileSync(lastFilePath, "utf8");
      weatherData = parseCSV(fileContent);
      console.log(`✅ Loaded last CSV: ${weatherData.length} records`);
    } catch (err) {
      console.error("❌ Error reading last CSV:", err);
    }
  } else {
    console.log("⚠️ No CSV file found. Upload one using /upload.");
  }
}

// ---------------- JWT Middleware ----------------
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: "Unauthorized", message: "Authorization header missing" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ error: "TokenExpired", message: "Session expired, please login again" });
      }
      return res.status(403).json({ error: "InvalidToken", message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role)
      return res
        .status(403)
        .json({ error: "Forbidden", message: "You don't have permission to access this resource" });
    next();
  };
}

// ---------------- Routes ----------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/viewer", (req, res) => res.sendFile(path.join(__dirname, "public", "viewer.html")));
app.get("/uploader", (req, res) => res.sendFile(path.join(__dirname, "public", "uploader.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/create-user", (req, res) => res.sendFile(path.join(__dirname, "public", "create-user.html")));

// ---------------- User Registration ----------------
app.post("/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password || !role)
      return res.status(400).json({ error: "All fields are required" });
    if (!["admin", "viewer", "uploader"].includes(role))
      return res.status(400).json({ error: "Invalid role" });

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, role });
    await newUser.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------- User Login ----------------
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: "Invalid username or password" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Invalid username or password" });

    const token = jwt.sign(
      { username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    res.json({
      message: "Login successful",
      user: { username: user.username, role: user.role },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------- Weather CSV Upload ----------------

app.post("/upload", authenticateJWT, upload.single("csvFile"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const content = fs.readFileSync(req.file.path, "utf8");
    weatherData = parseCSV(content);

    const devices = await DeviceToken.find(); // {token, city}
    let successCount = 0, failureCount = 0;

    for (const device of devices) {
      const cityWeather = weatherData.find(w => 
        w.city.toLowerCase() === device.city.toLowerCase()
      );

      let title, body;
      if (cityWeather) {
        const today = cityWeather.forecast[0]; // assume first = today
        title = `Today's Weather in ${device.city}`;
        body = `Min: ${today.minTemp}°C, Max: ${today.maxTemp}°C`;
      } else {
        title = "Today's Weather";
        body = "No weather data available for your city.";
      }

      try {
        await admin.messaging().send({
          token: device.token,
          notification: { title, body },
        });
        successCount++;
      } catch (err) {
        console.error(`❌ Failed to send to ${device.token}:`, err);
        failureCount++;
      }
    }

    console.log(`📩 Notifications sent: ${successCount}, ⚠️ Failed: ${failureCount}`);
    res.json({ message: "File uploaded and notifications sent", records: weatherData.length });

  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Error processing file" });
  }
});



// ---------------- Register Device Token ----------------
app.post("/register-token", async (req, res) => {
  try {
    const { token, city } = req.body;
    if (!token) return res.status(400).json({ error: "Token is required" });

    // Check if city is in CSV list, else fallback
    const availableCities = weatherData.map((w) => w.city.toLowerCase());
    const finalCity = city && availableCities.includes(city.toLowerCase())
      ? city
      : "Addis Ababa";

    const existing = await DeviceToken.findOne({ token });

    if (!existing) {
      await new DeviceToken({ token, city: finalCity }).save();
      console.log(`✅ New device token registered: ${token}, city: ${finalCity}`);
    } else {
      existing.city = finalCity; // update city if token exists
      await existing.save();
      console.log(`🔄 Updated device token: ${token}, city: ${finalCity}`);
    }

    res.json({ message: "Token registered/updated successfully", city: finalCity });
  } catch (err) {
    console.error("Error registering token:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});



// ---------------- Weather Data (Public) ----------------
app.get("/weather", (req, res) => {
  const location = req.query.location;
  if (weatherData.length === 0)
    return res.status(404).json({ error: "No weather data available" });
  if (!location) return res.json(weatherData);

  const weather = weatherData.find(
    (w) => w.city.toLowerCase() === location.toLowerCase()
  );
  if (!weather) return res.status(404).json({ error: "Location not found" });
  res.json(weather);
});

app.get("/locations", (req, res) => {
  try {
    const locations = weatherData.map((w) => w.city).filter(Boolean);
    res.json(locations);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------- Stats (Protected) ----------------
app.get("/stats", authenticateJWT, (req, res) => {
  try {
    res.json({
      recordCount: weatherData.length,
      locations: [...new Set(weatherData.map((w) => w.city))].length,
      lastUpdated: fs.existsSync(lastFilePath)
        ? fs.statSync(lastFilePath).mtime
        : null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------- Feedback submission ----------------
app.post("/feedback", async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message)
      return res.status(400).json({ error: "All fields are required" });

    const newFeedback = new Feedback({ name, email, message });
    await newFeedback.save();
    res.status(201).json({ message: "Feedback submitted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------- Feedback fetching ----------------
app.get("/feedback", authenticateJWT, async (req, res) => {
  try {
    const feedbacks = await Feedback.find().sort({ createdAt: -1 });
    res.json(feedbacks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------- Start Server ----------------
app.listen(port, () => {
  console.log(`🌦️ Weather API running at http://localhost:${port}`);
  loadLastCSV();
});
