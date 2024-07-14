const express = require('express');
const router = express.Router();
const usersJWTController = require('../controllers/users_jwt');

// Rutas para los endpoints CRUD
router.get('/', usersJWTController.getAllUsers);
router.post('/login', usersJWTController.login);
router.post('/', usersJWTController.addUser);
router.get('/verify', usersJWTController.authenticateJWT);
module.exports = router;
