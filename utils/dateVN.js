// Tiện ích xử lý NGÀY / TUẦN theo múi giờ Việt Nam (UTC+7).
//
// Vì sao cần file này: server chạy trên Render theo giờ UTC. Nếu dùng
// new Date().toISOString() thì từ 00:00 đến 07:00 sáng giờ Việt Nam,
// hệ thống vẫn tưởng là "hôm qua" -> ghi nhật ký / giờ sử dụng bị lệch ngày.
// Toàn bộ ngày trong hệ thống được lưu dạng chuỗi "YYYY-MM-DD" theo giờ VN.

const VN_OFFSET_MS = 7 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

function pad(n) { return String(n).padStart(2, '0'); }

// Chuyển một thời điểm (Date) thành chuỗi ngày YYYY-MM-DD theo giờ VN
function dateStr(date = new Date()) {
    return new Date(date.getTime() + VN_OFFSET_MS).toISOString().slice(0, 10);
}

function todayVN() { return dateStr(new Date()); }

function parseParts(str) {
    const [y, m, d] = str.split('-').map(Number);
    return { y, m, d };
}

// Kiểm tra chuỗi có đúng dạng ngày hợp lệ YYYY-MM-DD hay không (vd: loại "2026-02-31")
function isValidDateStr(str) {
    if (typeof str !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
    const { y, m, d } = parseParts(str);
    const t = new Date(Date.UTC(y, m - 1, d));
    return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}

function addDays(str, n) {
    const { y, m, d } = parseParts(str);
    return new Date(Date.UTC(y, m - 1, d) + n * DAY_MS).toISOString().slice(0, 10);
}

// Số ngày chênh lệch (b - a), cả hai là YYYY-MM-DD
function diffDays(a, b) {
    const pa = parseParts(a), pb = parseParts(b);
    return Math.round((Date.UTC(pb.y, pb.m - 1, pb.d) - Date.UTC(pa.y, pa.m - 1, pa.d)) / DAY_MS);
}

// Ngày đầu tuần (THỨ HAI) của một ngày bất kỳ
function weekStartOf(str) {
    const { y, m, d } = parseParts(str);
    const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay(); // 0 = Chủ nhật
    return addDays(str, dow === 0 ? -6 : 1 - dow);
}

function currentWeekStart() { return weekStartOf(todayVN()); }

function weekEndOf(weekStart) { return addDays(weekStart, 6); }

// Thời điểm (Date) tương ứng 00:00 giờ VN của một ngày
function startInstant(str) {
    const { y, m, d } = parseParts(str);
    return new Date(Date.UTC(y, m - 1, d) - VN_OFFSET_MS);
}

// Ngày (giờ VN) thiết bị được tạo, lấy từ ObjectId của MongoDB
function createdDateOf(doc) {
    try {
        if (doc && doc._id && typeof doc._id.getTimestamp === 'function') return dateStr(doc._id.getTimestamp());
    } catch (e) { /* bỏ qua */ }
    return '1970-01-01';
}

// Tuần của một bản ghi nhật ký. Nhật ký cũ (trước khi có ghi bù) chưa có weekStart
// nên suy ra từ thời điểm tạo.
function weekStartOfLog(log) {
    if (log.weekStart) return log.weekStart;
    return weekStartOf(dateStr(new Date(log.createdAt)));
}

// Nhãn "dd/mm – dd/mm" cho một tuần
function weekLabel(weekStart) {
    const s = parseParts(weekStart);
    const e = parseParts(weekEndOf(weekStart));
    return `${pad(s.d)}/${pad(s.m)} – ${pad(e.d)}/${pad(e.m)}`;
}

module.exports = {
    dateStr, todayVN, isValidDateStr, addDays, diffDays, weekStartOf, currentWeekStart,
    weekEndOf, startInstant, createdDateOf, weekStartOfLog, weekLabel
};
