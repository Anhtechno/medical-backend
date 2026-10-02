// =================================================================
// FILE: server.js - Điểm khởi động ứng dụng.
// Toàn bộ logic nghiệp vụ đã được tách ra models/, routes/, middleware/, config/
// để dễ đọc và bảo trì hơn (thay vì 1 file ~1600 dòng như trước).
// =================================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');

const connectDB = require('./config/db');

const app = express();
const PORT = process.env.PORT || 3000;

// 1. MIDDLEWARE CHUNG
app.use(helmet());
// BẢO MẬT: đọc domain frontend từ biến môi trường FRONTEND_URL (đặt trong Render)
// thay vì hardcode, để đổi domain không cần sửa code + deploy lại.
const corsOptions = {
    origin: process.env.FRONTEND_URL || 'https://resilient-dieffenbachia-5881b7.netlify.app',
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 2. KẾT NỐI MONGODB
connectDB();

// 3. GẮN CÁC ROUTER (mỗi router tự khai báo path đầy đủ, vd '/api/equipment/:deptKey')
app.use(require('./routes/auth.routes'));
app.use(require('./routes/equipment.routes'));
app.use(require('./routes/reports.routes'));
app.use(require('./routes/incidents.routes'));
app.use(require('./routes/maintenance.routes'));
app.use(require('./routes/dashboard.routes'));
app.use(require('./routes/users.routes'));
app.use(require('./routes/technicians.routes'));
app.use(require('./routes/public.routes'));
app.use(require('./routes/logs.routes'));
app.use(require('./routes/documents.routes'));
app.use(require('./routes/chat.routes'));

// 4. XỬ LÝ LỖI UPLOAD (multer: quá dung lượng hoặc sai định dạng file)
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError || (err && /không được hỗ trợ/.test(err.message || ''))) {
        return res.status(400).json({ message: err.message || 'File tải lên không hợp lệ.' });
    }
    next(err);
});

// 5. KHỞI ĐỘNG SERVER
app.listen(PORT, () => {
    console.log(`Backend đang chạy tại địa chỉ: http://localhost:${PORT}`);
});
