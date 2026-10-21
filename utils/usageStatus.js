// Tính toán "còn thiếu gì chưa ghi" cho từng thiết bị:
//  - missingDays : các ngày gần đây chưa có giờ sử dụng (thanh thời gian hằng ngày)
//  - needsLog    : tuần hiện tại chưa có nhật ký
//  - missingWeeks: các tuần đã qua chưa có nhật ký
//  - loggedWeeks : các tuần (trong phạm vi cho phép ghi bù) đã có nhật ký
const UsageLog = require('../models/UsageLog');
const cfg = require('../config/usage');
const {
    todayVN, addDays, currentWeekStart, weekEndOf, weekStartOf, createdDateOf, weekStartOfLog, startInstant
} = require('./dateVN');

// Thiết bị đang ngừng hoạt động -> tạm khóa ghi nhận ở phía Khoa
const isLocked = (eq) => !!eq && eq.status === cfg.LOCKED_STATUS;

// Tuần đầu tiên được phép ghi (tuần chứa ngày bắt đầu áp dụng phần mềm)
const firstWeek = () => weekStartOf(cfg.GO_LIVE_DATE);

// Lấy các tuần đã ghi nhật ký của mọi thiết bị trong phạm vi: Map<equipmentId, Set<weekStart>>
async function loadLoggedWeeks(extraFilter = {}) {
    const earliestWeek = firstWeek();
    const logs = await UsageLog.find({
        ...extraFilter,
        $or: [
            { weekStart: { $gte: earliestWeek } },
            // Nhật ký cũ chưa có weekStart -> dựa vào thời điểm tạo
            { weekStart: { $exists: false }, createdAt: { $gte: startInstant(earliestWeek) } }
        ]
    }).select('equipmentId weekStart createdAt').lean();

    const map = new Map();
    for (const log of logs) {
        const id = log.equipmentId.toString();
        if (!map.has(id)) map.set(id, new Set());
        map.get(id).add(weekStartOfLog(log));
    }
    return map;
}

function computeUsageStatus(eq, loggedWeeksSet = new Set()) {
    const today = todayVN();
    const created = createdDateOf(eq);
    const recordedDays = new Set((eq.usageHistory || []).map(h => h.date));

    // Các ngày đã qua (từ ngày bắt đầu áp dụng hoặc ngày thiết bị được thêm, tùy ngày nào muộn hơn)
    // mà chưa có giờ sử dụng
    const missingDays = [];
    const startDay = created > cfg.GO_LIVE_DATE ? created : cfg.GO_LIVE_DATE;
    for (let d = addDays(today, -1); d >= startDay; d = addDays(d, -1)) {
        if (!recordedDays.has(d)) missingDays.push(d);
    }

    const curWeek = currentWeekStart();
    const needsLog = !loggedWeeksSet.has(curWeek);

    const missingWeeks = [];
    const fw = firstWeek();
    for (let wk = addDays(curWeek, -7); wk >= fw; wk = addDays(wk, -7)) {
        if (weekEndOf(wk) >= created && !loggedWeeksSet.has(wk)) missingWeeks.push(wk);
    }

    const loggedWeeks = [...loggedWeeksSet].filter(w => w <= curWeek).sort();
    return { today, needsLog, missingDays, missingWeeks, loggedWeeks };
}

// Gắn thông tin "còn thiếu" vào một thiết bị để gửi về giao diện.
// - Bỏ usageHistory (rất nặng, giao diện không cần).
// - dailyUsage chỉ hiển thị nếu đã ghi cho HÔM NAY (giờ VN), ngược lại là 0.
function decorateEquipment(eq, loggedWeeksSet) {
    const st = computeUsageStatus(eq, loggedWeeksSet);
    const locked = isLocked(eq);
    const { usageHistory, ...rest } = eq;
    const todayEntry = (usageHistory || []).find(h => h.date === st.today);
    let dailyUsage = 0;
    if (todayEntry) dailyUsage = todayEntry.hours;
    else if (eq.lastLogDate === st.today) dailyUsage = eq.dailyUsage;
    return {
        ...rest,
        dailyUsage,
        locked, // true: thiết bị đang "Ngừng hoạt động" -> Khoa tạm thời không ghi được
        // Thiết bị đang bị khóa thì không nhắc "còn thiếu"
        needsLog: locked ? false : st.needsLog,
        missingDayCount: locked ? 0 : st.missingDays.length,
        missingWeeks: locked ? [] : st.missingWeeks,
        loggedWeeks: st.loggedWeeks,
        hasMissing: !locked && (st.needsLog || st.missingDays.length > 0 || st.missingWeeks.length > 0)
    };
}

module.exports = { loadLoggedWeeks, computeUsageStatus, decorateEquipment, firstWeek, isLocked };
