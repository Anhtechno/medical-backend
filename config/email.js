const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Hàm gửi mail dùng chung
async function sendNotificationEmail(toEmail, subject, htmlContent) {
    try {
        await transporter.sendMail({
            from: '"Hệ thống QLTB Y Tế" <' + process.env.EMAIL_USER + '>',
            to: toEmail,
            subject: subject,
            html: htmlContent
        });
        console.log(`Đã gửi mail tới ${toEmail}`);
    } catch (error) {
        console.error('Lỗi gửi mail:', error);
    }
}

module.exports = { sendNotificationEmail };
