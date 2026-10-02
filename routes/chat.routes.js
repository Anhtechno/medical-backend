const express = require('express');
const router = express.Router();
const Equipment = require('../models/Equipment');
const Incident = require('../models/Incident');
const Maintenance = require('../models/Maintenance');
const departments = require('../data/departments');
const { authenticateToken } = require('../middleware/auth');

/// --- API CHAT VỚI AI (SỬA LỖI 404: DÙNG MODEL GEMINI-PRO) ---
router.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        
        // Lấy dữ liệu toàn bộ hệ thống
        const dbContext = await getSystemContext();

        // Cấu hình AI (Dùng model bạn đã test thành công)
        const API_KEY = process.env.GEMINI_API_KEY;
        const MODEL_NAME = "gemini-2.5-flash"; // Hoặc model 2.5/pro mà bạn thấy chạy được
        const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent?key=${API_KEY}`;

        // TẠO CÂU LỆNH (PROMPT) MỚI: MỞ RỘNG QUYỀN HẠN
        const systemInstruction = `
        BẠN LÀ TRỢ LÝ AI CHUYÊN GIA CỦA HỆ THỐNG QUẢN LÝ THIẾT BỊ Y TẾ.
        
        Dưới đây là DỮ LIỆU THỰC TẾ của bệnh viện (được cập nhật realtime):
        --------------------------------------------------
        ${dbContext}
        --------------------------------------------------

        QUY TẮC TRẢ LỜI CỦA BẠN:
        1. ĐỐI VỚI CÂU HỎI VỀ DỮ LIỆU (VD: "Máy nào đang hỏng?", "Tìm máy thở serial 123"):
           - Bắt buộc phải tra cứu trong phần dữ liệu bên trên để trả lời chính xác.
           - Nếu tìm thấy, hãy cung cấp chi tiết (Vị trí, tình trạng, serial).
        
        2. ĐỐI VỚI CÂU HỎI KIẾN THỨC/NGOÀI LỀ (VD: "Cách sửa máy thở?", "Viết mail xin nghỉ phép", "Chào hỏi"):
           - Đừng nói "không tìm thấy thông tin".
           - Hãy dùng kiến thức rộng lớn của bạn để trả lời như một chuyên gia tư vấn nhiệt tình.
           - Nếu hỏi về kỹ thuật sửa chữa, hãy đưa ra các bước gợi ý chuyên sâu.

        3. PHONG CÁCH:
           - Trả lời ngắn gọn, chuyên nghiệp, dùng tiếng Việt.
           - Luôn xưng hô là "Tôi" hoặc "Trợ lý AI".
        `;

        const payload = {
            contents: [{
                parts: [{ text: `${systemInstruction}\n\nNGƯỜI DÙNG HỎI: "${message}"\nTRẢ LỜI:` }]
            }]
        };

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`Google API Error: ${response.statusText}`);
        }

        const data = await response.json();
        const replyText = data.candidates[0].content.parts[0].text;
        
        res.json({ reply: replyText });

    } catch (error) {
        console.error("Lỗi Chatbot:", error);
        res.status(500).json({ reply: "Xin lỗi, tôi đang gặp chút trục trặc khi suy nghĩ. Thử lại sau nhé!" });
    }
});

// --- HÀM HỖ TRỢ AI: LẤY DỮ LIỆU TỔNG QUAN ---
async function getSystemContext() {
    try {
        // 1. Lấy TOÀN BỘ thiết bị (Chi tiết từng máy)
        // Lưu ý: Lấy các trường quan trọng để tiết kiệm token
        const allEquipments = await Equipment.find()
            .select('name serial status department manufacturer year dailyUsage')
            .lean();

        // 2. Lấy TOÀN BỘ lịch bảo trì sắp tới
        const maintenance = await Maintenance.find({ status: { $in: ['scheduled', 'in_progress'] } })
            .select('equipmentName serial scheduleDate type technician notes')
            .lean();

        // 3. Lấy TOÀN BỘ sự cố đang diễn ra
        const incidents = await Incident.find({ status: { $ne: 'resolved' } })
            .populate('assignedTo', 'fullName')
            .select('equipmentName serial departmentKey problemDescription assignedTo')
            .lean();

        // 4. Format dữ liệu thành văn bản dễ đọc cho AI
        const eqText = allEquipments.map(e => 
            `- ${e.name} (Serial: ${e.serial}) | Khoa: ${departments[e.department] || e.department} | Tình trạng: ${e.status} | Hãng: ${e.manufacturer}`
        ).join('\n');

        const mainText = maintenance.map(m => 
            `- Bảo trì ${m.type === 'periodic' ? 'định kỳ' : 'đột xuất'}: ${m.equipmentName} (${m.serial}) vào ngày ${new Date(m.scheduleDate).toLocaleDateString('vi-VN')}`
        ).join('\n');

        const incText = incidents.map(i => 
            `- SỰ CỐ: ${i.equipmentName} (${i.serial}) tại ${departments[i.departmentKey] || i.departmentKey}. Lỗi: "${i.problemDescription}". Kỹ sư: ${i.assignedTo ? i.assignedTo.fullName : 'Chưa giao'}`
        ).join('\n');

        // 5. Tổng hợp lại
        return `
        === DỮ LIỆU HỆ THỐNG BỆNH VIỆN ===
        
        1. DANH SÁCH THIẾT BỊ HIỆN CÓ:
        ${eqText}

        2. LỊCH BẢO TRÌ SẮP TỚI:
        ${mainText || 'Không có lịch bảo trì nào.'}

        3. CÁC SỰ CỐ ĐANG CHỜ XỬ LÝ:
        ${incText || 'Hiện không có sự cố nào.'}
        `;
        
    } catch (error) {
        console.error("Lỗi lấy context:", error);
        return "Hệ thống đang gặp lỗi truy xuất dữ liệu.";
    }
}

module.exports = router;
