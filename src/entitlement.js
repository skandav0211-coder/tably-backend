const { DAY, nowIso } = require('./util');

// Authoritative subscription state for a business (SRS §4). Never derived from the client.
function entitlement(db, businessId, at = nowIso()) {
  const biz = db.prepare('SELECT * FROM businesses WHERE id=?').get(businessId);
  const none = { status: 'none', paid: false };
  if (!biz) return none;
  if (biz.status === 'suspended') return { status: 'suspended', paid: false, message: 'Account suspended' };
  const subs = db.prepare('SELECT * FROM subscriptions WHERE business_id=? ORDER BY created_at DESC, rowid DESC').all(businessId);
  const grace = Number(db.prepare("SELECT value FROM settings WHERE key='grace_days'").get().value) || 0;
  const active = subs.find(s => s.status === 'active' && s.start_date <= at && s.end_date > at);
  if (active) {
    const daysLeft = Math.ceil((new Date(active.end_date) - new Date(at)) / DAY);
    return { status: daysLeft <= 30 ? 'expiring_soon' : 'active', paid: true, daysLeft, subscription: active, message: active.admin_message };
  }
  const bad = subs.find(s => s.status === 'suspended' || s.status === 'revoked');
  if (bad) return { status: 'suspended', paid: false, subscription: bad, message: bad.admin_message };
  const pending = subs.find(s => s.status === 'pending');
  if (pending) return { status: 'pending', paid: false, subscription: pending, message: pending.admin_message };
  const ended = subs.find(s => s.status === 'active' && s.end_date <= at);
  if (ended) {
    const inGrace = grace > 0 && new Date(ended.end_date).getTime() + grace * DAY > new Date(at).getTime();
    return { status: inGrace ? 'grace' : 'expired', paid: inGrace, subscription: ended };
  }
  const rej = subs.find(s => s.status === 'rejected');
  if (rej) return { status: 'rejected', paid: false, subscription: rej, message: rej.admin_message };
  return none;
}
module.exports = { entitlement };
