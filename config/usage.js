// Cấu hình cho tính năng nhật ký sử dụng & giờ hoạt động hằng ngày.
module.exports = {
    // Số ngày tối đa được phép ghi bù giờ sử dụng (tính từ hôm nay trở về trước)
    BACKFILL_DAYS: 30,
    // Số tuần tối đa được phép ghi bù nhật ký tuần (không tính tuần hiện tại)
    BACKFILL_WEEKS: 8,
    // Cửa sổ nhắc nhở: số ngày gần nhất mà thiếu giờ sử dụng thì cảnh báo
    MISSING_DAYS_WINDOW: 7,
    // Cửa sổ nhắc nhở: số tuần đã qua mà thiếu nhật ký thì cảnh báo
    MISSING_WEEKS_WINDOW: 4,
    // Công suất chuẩn tính hiệu suất: số giờ tối đa một thiết bị có thể chạy trong ngày
    RATED_HOURS_PER_DAY: 24,
    // Ngưỡng màu hiệu suất (theo % công suất): trên mức 1 = vàng (cao), trên mức 2 = đỏ (quá tải)
    EFFICIENCY_HIGH: 50,
    EFFICIENCY_OVERLOAD: 80
};
