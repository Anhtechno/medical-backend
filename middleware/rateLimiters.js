const rateLimit = require('express-rate-limit');

// BẢO MẬT: giới hạn số lần thử đăng nhập/đăng ký để chống brute-force mật khẩu.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 phút
    max: 20, // tối đa 20 request/IP trong 15 phút
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Bạn đã thử quá nhiều lần. Vui lòng thử lại sau ít phút.' }
});

module.exports = { authLimiter };
