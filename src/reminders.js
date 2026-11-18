const { entitlement } = require('./entitlement');
const { nowIso } = require('./util');

// Sends each reminder threshold (e.g. 30/15/7/1 days) once per subscription (SRS §4.2).
function runReminders(db, notify) {
  const days = db.prepare("SELECT value FROM settings WHERE key='reminder_days'").get().value.split(',').map(Number).filter(n => n > 0).sort((a, b) => a - b);
  let sent = 0;
  for (const { id: bid } of db.prepare('SELECT id FROM businesses').all()) {
    const e = entitlement(db, bid, nowIso());
    if (!e.paid || e.daysLeft == null || !e.subscription) continue;
    const t = days.find(d => e.daysLeft <= d);
    if (t == null) continue;
    const sid = e.subscription.id;
    if (db.prepare('SELECT 1 FROM reminders_sent WHERE subscription_id=? AND days=?').get(sid, t)) continue;
    db.transaction(() => {
      for (const d of days.filter(d => d >= t)) db.prepare('INSERT OR IGNORE INTO reminders_sent VALUES (?,?)').run(sid, d);
      notify(bid, 'Subscription expiring soon', `Your subscription expires in ${e.daysLeft} day(s) on ${e.subscription.end_date.slice(0, 10)}. Submit a renewal to avoid interruption.`);
    })();
    sent++;
  }
  return sent;
}
module.exports = { runReminders };
