const { timingSafeEqual } = require('node:crypto');

function registerQueueRecovery(app, store, secret) {
  const authorize = (req, res, next) => {
    const provided = req.headers['x-webhook-secret'];
    if (!secret || typeof provided !== 'string' || Buffer.byteLength(provided) !== Buffer.byteLength(secret)
        || !timingSafeEqual(Buffer.from(provided), Buffer.from(secret))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.set('Cache-Control', 'no-store');
    next();
  };
  app.get('/api/queue/held', authorize, async (req, res) => {
    const rawOffset = req.query.offset ?? '0';
    if (typeof rawOffset !== 'string' || !/^\d+$/.test(rawOffset) || !Number.isSafeInteger(Number(rawOffset))) {
      return res.status(400).json({ error: 'Invalid offset' });
    }
    try { return res.json({ items: await store.listHeldItems(Number(rawOffset)) }); }
    catch { return res.status(503).json({ error: 'Queue unavailable' }); }
  });
  app.post('/api/queue/held/:id/retry', authorize, async (req, res) => {
    if (!req.params.id || req.params.id.length > 512) return res.status(400).json({ error: 'Invalid queue ID' });
    try {
      if (!await store.retryHeldItem(req.params.id)) return res.status(404).json({ error: 'Held item not found' });
      return res.status(202).json({ status: 'queued' });
    } catch { return res.status(503).json({ error: 'Queue recovery unavailable; item retained' }); }
  });
}
module.exports = { registerQueueRecovery };
