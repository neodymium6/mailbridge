const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { registerQueueRecovery } = require('../lib/queue-recovery');

test('recovery API authenticates, bounds listing, and never exposes backend errors', async t => {
  let calls=0;
  const app=express();
  registerQueueRecovery(app, {
    listHeldItems: async offset => { calls++; return [{ id:'fixture',offset }]; },
    retryHeldItem: async id => { calls++; if(id==='broken') throw new Error('PRIVATE KEY'); return id==='fixture'; }
  }, 'synthetic-secret');
  const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const base=`http://127.0.0.1:${server.address().port}`;
  const headers={'X-Webhook-Secret':'synthetic-secret'};
  assert.equal((await fetch(`${base}/api/queue/held`)).status,403);
  assert.equal((await fetch(`${base}/api/queue/held/fixture/retry`,{method:'POST'})).status,403);
  assert.equal(calls,0);
  for(const offset of ['-1','1.5','NaN','9007199254740992']) {
    assert.equal((await fetch(`${base}/api/queue/held?offset=${offset}`,{headers})).status,400);
  }
  const listed=await fetch(`${base}/api/queue/held?offset=100`,{headers});
  assert.equal(listed.headers.get('cache-control'),'no-store');
  assert.deepEqual(await listed.json(),{items:[{id:'fixture',offset:100}]});
  assert.equal((await fetch(`${base}/api/queue/held/fixture/retry`,{method:'POST',headers})).status,202);
  assert.equal((await fetch(`${base}/api/queue/held/missing/retry`,{method:'POST',headers})).status,404);
  const failed=await fetch(`${base}/api/queue/held/broken/retry`,{method:'POST',headers});
  assert.equal(failed.status,503);
  assert.ok(!(await failed.text()).includes('PRIVATE KEY'));
});
