const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
const path = require('path');

// Array to store users
let users = [];  

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, "public")));


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secretkey',  
  resave: false,
  saveUninitialized: false
}));

// Home Page
app.get('/', (req, res) => res.render('index'));

// Register Route
app.get('/register', (req, res) => res.render('register'));  // Registration Page
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Check if user already exists
  if (users.find(u => u.email === email)) {
    return res.render('register', { error: 'User with this email already exists.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  // If no users exist, make the first one an admin, else regular user
  const role = users.length === 0 ? 'admin' : 'user';  

  users.push({ username, email, password: hashedPassword, role });
  res.redirect('/login');
});

// Login Route
app.get('/login', (req, res) => res.render('login'));  
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  // Check if user exists and password matches
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.render('login', { error: 'Invalid credentials' });
  }

  // Store the user in the session
  req.session.user = user;

 
  res.redirect('/landing');
});


app.get('/landing', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');  
  }

  
  if (req.session.user.role === 'admin') {
    return res.render('admin', { users });  // Admin dashboard, show all users
  }

  
  res.render('dashboard', { username: req.session.user.username });
});

// Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect('/landing'); 
    }
    res.redirect('/login');  
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
