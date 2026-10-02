const cloudinary = require('cloudinary').v2;
const multer = require('multer');

// Cấu hình Cloudinary bằng các biến môi trường chúng ta đã thêm
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Thiết lập nơi lưu trữ file cho multer
// Thay thế toàn bộ khối const storage cũ bằng phiên bản này

// BẢO MẬT: giới hạn kích thước file và chỉ cho phép các định dạng dùng thật
// (avatar kỹ sư = ảnh; tài liệu thiết bị = ảnh/PDF/Word/Excel).
const ALLOWED_UPLOAD_MIME_TYPES = new Set([
    'image/jpeg', 'image/png', 'image/webp', 'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
]);
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 15 * 1024 * 1024 }, // tối đa 15MB / file
    fileFilter: (req, file, cb) => {
        if (ALLOWED_UPLOAD_MIME_TYPES.has(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Định dạng file không được hỗ trợ.'));
        }
    }
});

module.exports = { cloudinary, upload };
