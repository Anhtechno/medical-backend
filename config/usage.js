// Cấu hình cho tính năng nhật ký sử dụng & giờ hoạt động hằng ngày.
module.exports = {
    // Ngày bắt đầu áp dụng phần mềm. Các Khoa được ghi bù (cả nhật ký tuần lẫn giờ sử dụng
    // hằng ngày) từ ngày này trở đi. Dạng YYYY-MM-DD. Đổi giá trị này nếu muốn lùi/tiến mốc.
    // (Giao diện app.js cũng có hằng số GO_LIVE_DATE cùng giá trị - sửa cả hai nơi.)
    GO_LIVE_DATE: '2026-01-01',
    // Thiết bị ở trạng thái này thì tài khoản Khoa tạm thời không ghi nhật ký / giờ sử dụng được
    LOCKED_STATUS: 'inactive',
    LOCKED_MESSAGE: 'Thiết bị đang ở trạng thái "Ngừng hoạt động" nên tạm thời không thể ghi nhận. Khi Admin chuyển thiết bị về "Hoạt động" thì Khoa mới ghi được.',
    // Công suất chuẩn tính hiệu suất: số giờ tối đa một thiết bị có thể chạy trong ngày
    RATED_HOURS_PER_DAY: 24,
    // Ngưỡng màu hiệu suất (theo % công suất): trên mức 1 = vàng (cao), trên mức 2 = đỏ (quá tải)
    EFFICIENCY_HIGH: 50,
    EFFICIENCY_OVERLOAD: 80
};
