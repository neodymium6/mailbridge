const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const sqlite3 = require('sqlite3').verbose();

const { createAuditLogStore } = require('../lib/audit-log-store');
const { createQueueCrypto } = require('../lib/queue-crypto');
const { createQueueManager, isPermanentDeliveryError } = require('../lib/queue-manager');
const { createQueueStore } = require('../lib/queue-store');
const { all, close, get, run } = require('../lib/sqlite-helpers');

function randomMasterKey() {
  return crypto.randomBytes(32).toString('base64');
}

async function createHarness(t, options = {}) {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mailbridge-queue-'));

  const dataDir = path.join(rootDir, 'data');
  const secretsDir = path.join(rootDir, 'secrets');
  fs.mkdirSync(path.join(dataDir, 'queue'), { recursive: true });
  fs.mkdirSync(secretsDir, { recursive: true });

  let currentTime = new Date(options.now || '2026-03-28T00:00:00.000Z');
  const queueCrypto = createQueueCrypto({
    masterKey: options.masterKey || randomMasterKey()
  });
  const auditStore = createAuditLogStore({
    dbPath: path.join(dataDir, 'mailbridge.db'),
    queueCrypto,
    env: {
      AUDIT_LOG_RETENTION_DAYS: options.retentionDays || '1'
    },
    now: () => currentTime
  });
  await auditStore.init();
  const secretsDbPath = path.join(secretsDir, 'secrets.db');
  const secretsDb = new sqlite3.Database(secretsDbPath);

  const queueStore = createQueueStore({
    db: secretsDb,
    dataDir,
    queueCrypto,
    auditStore,
    now: () => currentTime
  });
  await queueStore.init();

  let closed = false;
  async function cleanup() {
    if (closed) return;
    closed = true;
    await close(secretsDb);
    await close(auditStore.db);
  }

  t.after(async () => {
    await cleanup();
    fs.rmSync(rootDir, { recursive: true, force: true });
  });

  return {
    auditStore,
    close: cleanup,
    dataDir,
    dbPath: path.join(dataDir, 'mailbridge.db'),
    queueCrypto,
    queueStore,
    rootDir,
    secretsDb,
    secretsDbPath,
    setNow(value) {
      currentTime = new Date(value);
    }
  };
}

test('explicit permanent=false keeps 5xx sendgrid-style errors retryable', () => {
  assert.equal(
    isPermanentDeliveryError({ statusCode: 503, permanent: false }),
    false
  );
});

test('explicit permanent=true still wins regardless of status code', () => {
  assert.equal(
    isPermanentDeliveryError({ statusCode: 429, permanent: true }),
    true
  );
});

test('429 remains temporary when no explicit permanent flag is provided', () => {
  assert.equal(isPermanentDeliveryError({ statusCode: 429 }), false);
});

test('smtp 5xx remains permanent when no explicit permanent flag is provided', () => {
  assert.equal(isPermanentDeliveryError({ responseCode: 550 }), true);
});

test('SMTP temporary responses and HTTP service failures remain retryable', () => {
  for (const responseCode of [421, 450, 451, 452]) {
    assert.equal(isPermanentDeliveryError({ responseCode }), false, `SMTP ${responseCode}`);
  }
  for (const statusCode of [408, 429, 500, 502, 503, 504]) {
    assert.equal(isPermanentDeliveryError({ statusCode }), false, `HTTP ${statusCode}`);
  }
  assert.equal(isPermanentDeliveryError({ statusCode: 400 }), true);
});

test('queued mail survives an SMTP 451 and delivers on the next attempt', async (t) => {
  const harness = await createHarness(t);
  await harness.queueStore.addToQueue('', 'dest@example.com', 'Subject: DSN\r\n\r\nbody');
  let calls = 0;
  const manager = createQueueManager({
    store: harness.queueStore, auditStore: harness.auditStore, maxQueueAttempts: 3,
    async deliverQueuedMessage(message) {
      assert.equal(message.sender, '');
      if (++calls === 1) throw Object.assign(new Error('Try again later'), { responseCode: 451 });
    }
  });
  await manager.processQueue();
  assert.equal(await harness.queueStore.countQueueItems(), 1);
  await manager.processQueue();
  assert.equal(calls, 2);
  assert.equal(await harness.queueStore.countQueueItems(), 0);
});

test('concurrent audit events form one continuous authenticated chain', async (t) => {
  const harness = await createHarness(t);
  await Promise.all(Array.from({ length: 10 }, (_, i) => harness.auditStore.logEvent({ eventType: 'delivered', requestId: `request-${i}` })));
  const rows = await all(harness.auditStore.db, 'SELECT previous_event_hmac, event_hmac FROM audit_events ORDER BY id');
  assert.equal(rows.length, 10);
  assert.equal(rows[0].previous_event_hmac, null);
  for (let i = 1; i < rows.length; i++) assert.equal(rows[i].previous_event_hmac, rows[i - 1].event_hmac);
});

test('persisted queue acceptance is not undone by an audit failure', async (t) => {
  const harness = await createHarness(t);
  harness.auditStore.logEvent = async () => { throw new Error('synthetic audit failure'); };
  const id = await harness.queueStore.addToQueue('', 'dest@example.com', 'Subject: DSN\r\n\r\nbody');
  assert.equal(typeof id, 'string');
  const rows = await harness.queueStore.listQueueItems();
  assert.equal(rows.length, 1);
  assert.equal((await harness.queueStore.loadQueuedMessage(rows[0])).sender, '');
});

test('queued messages are encrypted at rest and db does not store raw content', async (t) => {
  const harness = await createHarness(t);
  const rawEmail = 'Subject: Hello\r\n\r\nThis is sensitive mail';

  const queueId = await harness.queueStore.addToQueue(
    'alice@example.com',
    'bob@example.com',
    rawEmail,
    'local_mail',
    {
      direction: 'inbound',
      requestId: 'req-1',
      sourceIp: '203.0.113.10',
      senderDomain: 'example.com'
    }
  );

  const queueFile = path.join(harness.dataDir, 'queue', `${queueId}.eml`);
  const encryptedBytes = fs.readFileSync(queueFile);
  assert.equal(encryptedBytes.toString('utf8').includes('This is sensitive mail'), false);
  assert.equal(encryptedBytes.toString('utf8').includes('alice@example.com'), false);

  const queueItem = await get(harness.secretsDb, 'SELECT * FROM queue_items WHERE id = ?', [queueId]);
  assert.equal(typeof queueItem.per_message_secret, 'string');
  assert.equal(Object.prototype.hasOwnProperty.call(queueItem, 'raw_content'), false);

  const auditEvent = await get(harness.auditStore.db, 'SELECT * FROM audit_events WHERE queue_id = ?', [queueId]);
  assert.ok(auditEvent.sender_hash);
  assert.notEqual(auditEvent.sender_hash, 'alice@example.com');

  const columns = await all(harness.secretsDb, 'PRAGMA table_info(queue_items)');
  assert.equal(columns.some((column) => column.name === 'raw_content'), false);
  const auditQueueTable = await get(
    harness.auditStore.db,
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'queue_items'"
  );
  assert.equal(auditQueueTable, null);
});

test('queued messages require both the db secret and QUEUE_MASTER_KEY to decrypt', async (t) => {
  const masterKey = randomMasterKey();
  const harness = await createHarness(t, { masterKey });

  const queueId = await harness.queueStore.addToQueue(
    'alice@example.com',
    'bob@example.com',
    'Subject: Hi\r\n\r\nEncrypted',
    'local_mail'
  );

  const row = await get(harness.secretsDb, 'SELECT * FROM queue_items WHERE id = ?', [queueId]);
  await harness.close();

  const wrongQueueCrypto = createQueueCrypto({ masterKey: randomMasterKey() });
  const wrongAuditStore = createAuditLogStore({
    dbPath: harness.dbPath,
    queueCrypto: wrongQueueCrypto,
    env: { AUDIT_LOG_RETENTION_DAYS: '1' }
  });
  await wrongAuditStore.init();
  const wrongSecretsDb = new sqlite3.Database(harness.secretsDbPath);
  const wrongQueueStore = createQueueStore({
    db: wrongSecretsDb,
    dataDir: harness.dataDir,
    queueCrypto: wrongQueueCrypto,
    auditStore: wrongAuditStore
  });
  await wrongQueueStore.init();

  await assert.rejects(
    wrongQueueStore.loadQueuedMessage(row),
    /unable to authenticate data|Unsupported state or unable to authenticate data/
  );

  await close(wrongSecretsDb);
  await close(wrongAuditStore.db);
});

test('queue manager retries temporary failures and removes delivered messages', async (t) => {
  const harness = await createHarness(t);
  const rawEmail = 'Subject: Retry\r\n\r\nHello';
  await harness.queueStore.addToQueue('alice@example.com', 'bob@example.com', rawEmail, 'local_mail');

  let attempts = 0;
  const queueManager = createQueueManager({
    store: harness.queueStore,
    auditStore: harness.auditStore,
    maxQueueAttempts: 3,
    async deliverQueuedMessage(message) {
      attempts += 1;
      if (attempts === 1) {
        const error = new Error('temporary network issue');
        error.statusCode = 429;
        throw error;
      }
      assert.equal(message.sender, 'alice@example.com');
      assert.equal(message.recipient, 'bob@example.com');
      assert.equal(message.raw_content, rawEmail);
    }
  });

  await queueManager.processQueue();
  let queueRows = await harness.queueStore.listQueueItems();
  assert.equal(queueRows.length, 1);
  assert.equal(queueRows[0].attempts, 1);

  await queueManager.processQueue();
  queueRows = await harness.queueStore.listQueueItems();
  assert.equal(queueRows.length, 0);

  const auditRows = await all(harness.auditStore.db, 'SELECT event_type, outcome FROM audit_events ORDER BY id');
  assert.deepEqual(
    auditRows.map((row) => `${row.event_type}:${row.outcome}`),
    [
      'queued:queued',
      'retry:attempt_started',
      'retry:temporary_failure',
      'retry:attempt_started',
      'delivered:delivered'
    ]
  );
});

test('queue manager retains permanently failed messages outside the active queue', async (t) => {
  const harness = await createHarness(t);
  await harness.queueStore.addToQueue('alice@example.com', 'bob@example.com', 'Subject: Fail\r\n\r\nNope', 'sendgrid');

  const queueManager = createQueueManager({
    store: harness.queueStore,
    auditStore: harness.auditStore,
    maxQueueAttempts: 3,
    async deliverQueuedMessage() {
      const error = new Error('mailbox unavailable');
      error.responseCode = 550;
      throw error;
    }
  });

  await queueManager.processQueue();

  const queueRows = await harness.queueStore.listQueueItems();
  assert.equal(queueRows.length, 0);

  assert.equal(await harness.queueStore.countQueueItems(), 1);
  const held = await harness.queueStore.listHeldItems();
  assert.equal(held.length, 1);
  assert.equal(held[0].hold_reason, 'permanent_failure');

  const auditRow = await get(
    harness.auditStore.db,
    "SELECT event_type, outcome FROM audit_events WHERE event_type = 'delivery_failed' ORDER BY id DESC LIMIT 1"
  );
  assert.deepEqual(auditRow, {
    event_type: 'delivery_failed',
    outcome: 'permanent_failure'
  });
});

test('legacy sqlite queue rows are migrated into encrypted queue files', async (t) => {
  const harness = await createHarness(t);
  const legacyDbPath = path.join(harness.rootDir, 'mail_queue.sqlite');
  const legacyDb = new sqlite3.Database(legacyDbPath);

  await run(legacyDb, `CREATE TABLE queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    recipient TEXT,
    raw_content TEXT,
    target TEXT DEFAULT 'local_mail',
    attempts INTEGER DEFAULT 0,
    last_attempt DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(
    legacyDb,
    'INSERT INTO queue (sender, recipient, raw_content, target, attempts, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    ['legacy@example.com', 'dest@example.com', 'Subject: Legacy\r\n\r\nQueued', 'local_mail', 2, '2026-03-27T00:00:00.000Z']
  );
  await close(legacyDb);

  const migratedCount = await harness.queueStore.migrateLegacyQueue(legacyDbPath);
  assert.equal(migratedCount, 1);
  assert.equal(fs.existsSync(legacyDbPath), false);

  const queueRows = await harness.queueStore.listQueueItems();
  assert.equal(queueRows.length, 1);
  assert.equal(queueRows[0].attempts, 2);

  const queuedMessage = await harness.queueStore.loadQueuedMessage(queueRows[0]);
  assert.equal(queuedMessage.sender, 'legacy@example.com');
  assert.equal(queuedMessage.recipient, 'dest@example.com');
  assert.equal(queuedMessage.rawContent, 'Subject: Legacy\r\n\r\nQueued');
});

test('current queue_items are migrated out of mailbridge.db into secrets.db', async (t) => {
  const harness = await createHarness(t);
  const queueFile = path.join(harness.dataDir, 'queue', 'migrated.eml');
  fs.writeFileSync(queueFile, Buffer.from('ciphertext'));
  await run(harness.auditStore.db, `CREATE TABLE queue_items (
    id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    per_message_secret TEXT NOT NULL,
    target TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_attempt_at TEXT,
    sender_hash TEXT,
    recipient_hash TEXT,
    source_ip_hash TEXT,
    sender_domain TEXT,
    request_id TEXT
  )`);
  await run(
    harness.auditStore.db,
    `INSERT INTO queue_items (
      id, file_name, per_message_secret, target, attempts, created_at, sender_hash, recipient_hash, source_ip_hash, sender_domain, request_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ['migrated-1', 'migrated.eml', 'c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2U=', 'local_mail', 1, '2026-03-27T00:00:00.000Z', 'sender-h', 'recipient-h', 'ip-h', 'example.com', 'req-1']
  );

  const migratedCount = await harness.queueStore.migrateQueueItemsFromDatabase(harness.auditStore.db, 'audit-db');
  assert.equal(migratedCount, 1);

  const migratedRow = await get(harness.secretsDb, 'SELECT * FROM queue_items WHERE id = ?', ['migrated-1']);
  assert.equal(migratedRow.file_name, 'migrated.eml');

  const oldTable = await get(
    harness.auditStore.db,
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'queue_items'"
  );
  assert.equal(oldTable, null);
});

test('audit log pruning honors AUDIT_LOG_RETENTION_DAYS and event chain is linked', async (t) => {
  const harness = await createHarness(t, { now: '2026-03-25T00:00:00.000Z', retentionDays: '1' });

  await harness.auditStore.logEvent({
    requestId: 'req-old',
    eventType: 'delivered',
    direction: 'inbound',
    target: 'local_mail',
    outcome: 'delivered',
    sender: 'first@example.com',
    recipient: 'one@example.com',
    sourceIp: '198.51.100.7'
  });

  harness.setNow('2026-03-25T00:10:00.000Z');
  await harness.auditStore.logEvent({
    requestId: 'req-new',
    eventType: 'ai_result',
    direction: 'inbound',
    target: 'local_mail',
    outcome: 'not_spam',
    sender: 'second@example.com',
    recipient: 'two@example.com',
    sourceIp: '198.51.100.8'
  });

  let rows = await all(harness.auditStore.db, 'SELECT previous_event_hmac, event_hmac, sender_hash FROM audit_events ORDER BY id');
  assert.equal(rows.length, 2);
  assert.equal(rows[0].previous_event_hmac, null);
  assert.equal(rows[1].previous_event_hmac, rows[0].event_hmac);
  assert.ok(rows[0].sender_hash);

  harness.setNow('2026-03-27T00:10:00.000Z');
  await harness.auditStore.pruneExpiredEvents();
  rows = await all(harness.auditStore.db, 'SELECT id FROM audit_events ORDER BY id');
  assert.equal(rows.length, 0);
});

test('exhausted mail survives reopen, does not starve active mail, and can be requeued', async t => {
  const h = await createHarness(t);
  const id = await h.queueStore.addToQueue('a@example.com', 'b@example.com', 'Subject: preserved\r\n\r\nretained', 'local_mail', { attempts: 3 });
  let delivered = 0;
  const manager = createQueueManager({ store: h.queueStore, auditStore: h.auditStore, maxQueueAttempts: 3,
    deliverQueuedMessage: async () => { delivered++; } });
  await manager.processQueue();
  assert.equal(delivered, 0);
  assert.equal((await h.queueStore.listHeldItems())[0].hold_reason, 'max_attempts_exceeded');
  assert.equal(await h.queueStore.countQueueItems(), 1);
  const bytes = fs.readFileSync(path.join(h.dataDir, 'queue', `${id}.eml`));
  assert.ok(!bytes.includes(Buffer.from('retained')));
  // Reopen the actual database with the same keys, as after a service restart.
  const db = new sqlite3.Database(h.secretsDbPath);
  const reopened = createQueueStore({ db, dataDir: h.dataDir, queueCrypto: h.queueCrypto, auditStore: h.auditStore });
  await reopened.init();
  try {
    const held = await reopened.listHeldItems();
    assert.equal(held.length, 1);
    assert.deepEqual(Object.keys(held[0]).sort(), ['attempts','created_at','held_at','hold_reason','id','target']);
    assert.equal((await reopened.listQueueItems()).length, 0);
    await h.queueStore.addToQueue('c@example.com','d@example.com','Subject: next\r\n\r\nnext');
    await manager.processQueue();
    assert.equal(delivered, 1);
    assert.equal(await reopened.retryHeldItem(id), true);
    assert.equal(await reopened.retryHeldItem(id), false);
    assert.equal(await reopened.retryHeldItem('missing'), false);
    assert.equal((await reopened.listQueueItems())[0].attempts, 0);
    await manager.processQueue();
    assert.equal(delivered, 2);
    assert.equal(await reopened.countQueueItems(), 0);
    assert.equal(fs.existsSync(path.join(h.dataDir, 'queue', `${id}.eml`)), false);
  } finally { await close(db); }
});

test('held-item listing paginates and excludes secret material', async t => {
  const h = await createHarness(t);
  for (let i=0; i<102; i++) {
    const id = await h.queueStore.addToQueue('a@example.com','b@example.com','Subject: private\r\n\r\nprivate');
    await h.queueStore.holdQueueItem(id, 'permanent_failure');
  }
  assert.equal((await h.queueStore.listQueueItems()).length, 0);
  const first = await h.queueStore.listHeldItems();
  const second = await h.queueStore.listHeldItems(100);
  assert.equal(first.length,100);
  assert.equal(second.length,2);
  assert.equal(new Set([...first,...second].map(row=>row.id)).size,102);
  assert.ok(!JSON.stringify(first).includes('per_message_secret'));
  await assert.rejects(h.queueStore.listHeldItems(-1), /Invalid offset/);
});

test('damaged retained mail cannot be requeued and remains held', async t => {
  const h = await createHarness(t);
  const id = await h.queueStore.addToQueue('a@example.com','b@example.com','Subject: held\r\n\r\nheld');
  await h.queueStore.holdQueueItem(id,'permanent_failure');
  fs.writeFileSync(path.join(h.dataDir,'queue',`${id}.eml`),'broken');
  await assert.rejects(h.queueStore.retryHeldItem(id));
  assert.equal((await h.queueStore.listHeldItems()).length,1);
});

test('old queue schema migrates without losing encrypted messages', async t => {
  const h=await createHarness(t);
  const id=await h.queueStore.addToQueue('a@example.com','b@example.com','Subject: old\r\n\r\nold');
  await run(h.secretsDb,'ALTER TABLE queue_items DROP COLUMN held_at');
  await run(h.secretsDb,'ALTER TABLE queue_items DROP COLUMN hold_reason');
  await h.queueStore.init();
  await h.queueStore.init();
  assert.equal((await h.queueStore.listQueueItems())[0].id,id);
  assert.equal((await h.queueStore.loadQueuedMessage((await h.queueStore.listQueueItems())[0])).rawContent,'Subject: old\r\n\r\nold');
});
