require('dotenv').config();
const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

// Connect to PostgreSQL using DATABASE_URL
const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false,
    }
  }
});

// Models
const User = sequelize.define('User', {
  name: { type: DataTypes.STRING },
  email: { type: DataTypes.STRING, unique: true, allowNull: false },
  password: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('employee', 'employer'), defaultValue: 'employee' }
});

const Task = sequelize.define('Task', {
  title: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT },
  completed: { type: DataTypes.BOOLEAN, defaultValue: false }
});

// Relationships
User.hasMany(Task);
Task.belongsTo(User);

// Middleware
app.use(express.json());

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Routes

// Register
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword, role });
    res.status(201).json({ message: 'User registered', user: { id: user.id, email: user.email } });
  } catch (err) {
    res.status(400).json({ error: 'Email already used or invalid data' });
  }
});

// Login
// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Incorrect password' });

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);

  // 🟢 UYU NIWO MURONGO DUTSINZEMO — dutanga na `user` object
  res.json({
    message: 'Login successful',
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role
    }
  });
});


// Create Task
app.post('/tasks', authenticateToken, async (req, res) => {
  const { title, description } = req.body;
  const task = await Task.create({ title, description, UserId: req.user.id });
  res.status(201).json(task);
});

// Get My Tasks
app.get('/tasks', authenticateToken, async (req, res) => {
  const tasks = await Task.findAll({ where: { UserId: req.user.id } });
  res.json(tasks);
});

// Update Task
app.put('/tasks/:id', authenticateToken, async (req, res) => {
  const { title, description, completed } = req.body;
  const task = await Task.findOne({ where: { id: req.params.id, UserId: req.user.id } });
  if (!task) return res.status(404).json({ error: 'Task not found' });

  task.title = title ?? task.title;
  task.description = description ?? task.description;
  task.completed = completed ?? task.completed;
  await task.save();
  res.json(task);
});

// Delete Task
app.delete('/tasks/:id', authenticateToken, async (req, res) => {
  const task = await Task.findOne({ where: { id: req.params.id, UserId: req.user.id } });
  if (!task) return res.status(404).json({ error: 'Task not found' });

  await task.destroy();
  res.json({ message: 'Task deleted' });
});

// Start server
sequelize.sync().then(() => {
  console.log('Database synced');
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
});
