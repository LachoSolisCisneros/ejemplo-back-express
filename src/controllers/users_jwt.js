const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
// Configuración de la base de datos (igual que antes)
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE
});
db.connect((err) => {
  if (err) throw err;
  console.log('UsersJWT-Conexión a la BD establecida');
});

exports.login = async (req, res) => {
  const { email, password } = req.body;
  //console.log("Datos recibidos:", email, password);
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, result) => {
    if (err) {
      console.error("Error en la consulta SQL:", err);
      res.status(500).send('Error en el servidor');
      return;
    }
    if (!result || result.length === 0) {
      console.log("No se encontró el usuario");
      return res.status(401).send('Credenciales inválidas');
    }

    const user = result[0];
    //console.log("Usuario encontrado:", user);

    const validPassword = await bcrypt.compare(password, user.password);
    //console.log("Contraseña válida:", validPassword);
    if (!validPassword) {
      return res.status(401).send('Credenciales inválidas');
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
};
// Middleware de autenticación
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403); 
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401); 
  }
};
exports.authenticateJWT = authenticateJWT;
// Rutas protegidas con autenticación JWT
exports.getAllUsers = [authenticateJWT, (req, res) => {
  db.query('SELECT * FROM users', (err, result) => {
    if (err) {
      res.status(500).send('Error al obtener los usuarios');
      throw err;
    }
    res.json(result);
  });
}];
exports.addUser = [authenticateJWT, (req, res) => {
  const newUser = req.body;
  // Hashear la contraseña antes de guardarla (bcrypt)
  bcrypt.hash(newUser.password, 10, (err, hash) => { // 10 es el número de rondas de hashing
    if (err) {
      res.status(500).send('Error al hashear la contraseña');
      throw err;
    }
    newUser.password = hash;    
    db.query('INSERT INTO users SET ?', newUser, (err, result) => {
      if (err) {
        res.status(500).send('Error al agregar el usuario');
        throw err;
      }
      res.status(201).send('Usuario agregado correctamente');
    });
  });
}];