const express = require('express');
const router = express.Router();
const Document = require('../models/Document');
const { authenticateToken, isAdmin } = require('../middleware/auth');
const { upload, cloudinary } = require('../config/upload');

// 10.14. API QUẢN LÝ TÀI LIỆU (TÍNH NĂNG MỚI)
// =================================================================

// Lấy danh sách tài liệu của một thiết bị
router.get('/api/documents/:equipmentId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { equipmentId } = req.params;
        const documents = await Document.find({ equipmentId: equipmentId }).sort({ createdAt: -1 });
        res.json(documents);
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi lấy danh sách tài liệu.' });
    }
});

// Upload một tài liệu mới
// Thay thế toàn bộ hàm router.post('/api/documents/upload...) cũ bằng hàm này
router.post('/api/documents/upload/:equipmentId', authenticateToken, isAdmin, upload.single('document'), async (req, res) => {
    try {
        const { equipmentId } = req.params;
        const { documentType } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ message: 'Không có file nào được tải lên.' });
        }

        // Tải file lên Cloudinary từ bộ nhớ đệm (buffer)
        const uploadResult = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                {
                    folder: 'equipment_documents',
                    resource_type: 'auto'
                },
                (error, result) => {
                    if (error) {
                        return reject(error);
                    }
                    resolve(result);
                }
            );
            uploadStream.end(req.file.buffer);
        });

        const newDocument = new Document({
            equipmentId: equipmentId,
            fileName: req.file.originalname,
            fileUrl: uploadResult.secure_url, // Lấy URL an toàn và chính xác từ kết quả
            cloudinaryId: uploadResult.public_id,
            documentType: documentType,
            uploadedBy: req.user.username
        });

        await newDocument.save();
        res.status(201).json(newDocument);

    } catch (error) {
        console.error("Lỗi khi upload tài liệu:", error);
        res.status(500).json({ message: 'Lỗi server khi upload tài liệu.' });
    }
});

// Xóa một tài liệu
router.delete('/api/documents/:documentId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { documentId } = req.params;
        const docToDelete = await Document.findById(documentId);

        if (!docToDelete) {
            return res.status(404).json({ message: 'Không tìm thấy tài liệu.' });
        }

        // Xóa file trên Cloudinary
        await cloudinary.uploader.destroy(docToDelete.cloudinaryId);
        
        // Xóa bản ghi trong database
        await Document.findByIdAndDelete(documentId);

        res.json({ message: 'Xóa tài liệu thành công.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi xóa tài liệu.' });
    }
});

module.exports = router;
