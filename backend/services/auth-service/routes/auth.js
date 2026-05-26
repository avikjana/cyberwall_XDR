const express = require('express');
const { register, login, refreshToken, getMe } = require('../controllers/authController');
const { protect } = require('../../shared/authMiddleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/refresh', refreshToken);
router.get('/me', protect, getMe);

module.exports = router;
