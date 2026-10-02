const mongoose = require('mongoose');

// Kết nối MongoDB — gọi 1 lần khi khởi động server (xem server.js)
function connectDB() {
    const MONGODB_URI = process.env.MONGODB_URI;
    mongoose.connect(MONGODB_URI)
        .then(() => console.log('Đã kết nối thành công tới MongoDB Atlas!'))
        .catch(err => console.error('!!! LỖI KẾT NỐI MONGODB:', err));
}

module.exports = connectDB;
