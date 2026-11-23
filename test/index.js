process.env.ENCRYPTION_SECRET = 'test-secret';
const test = require('tape');
const crypto = require('crypto');
const digestChallenge = require('..');

const secretKey = crypto.createHash('sha256').update('test-secret').digest('base64').substring(0, 32);
const encrypt = (text) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);
  const content = Buffer.concat([cipher.update(text), cipher.final()]);
  return JSON.stringify({iv: iv.toString('hex'), content: content.toString('hex')});
};

const realm = 'record.sip.example.com';
const uri = 'sip:agent@record.sip.example.com';
const authHeader = (username, password) => {
  const nonce = 'abc123';
  const response = digestChallenge.calculateResponse({username, realm, method: 'INVITE', nonce, uri}, password);
  return `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}", algorithm=MD5`;
};

function run({username, password, clients, hook, hookStatus = 500}) {
  const calls = {hook: 0};
  const logs = [];
  const logger = {
    debug() {},
    info: (...a) => logs.push(a),
    error: (...a) => logs.push(a)
  };
  global.fetch = async() => {
    calls.hook++;
    return hookStatus === 200 ?
      {status: 200, json: async() => ({status: 'ok'})} :
      {status: hookStatus, statusText: 'Server Error'};
  };
  const req = {
    method: 'INVITE',
    source_address: '192.0.2.1',
    source_port: 5060,
    headers: {},
    has: (h) => h === 'Authorization',
    get: () => authHeader(username, password),
    locals: {
      logger, realm, account_sid: 'acct',
      ...(hook && {registration_hook_url: 'https://hook.example.com/auth', registration_hook_method: 'POST'})
    },
    srf: {locals: {
      stats: {histogram() {}},
      AlertType: {WEBHOOK_STATUS_FAILURE: 'x', WEBHOOK_CONNECTION_FAILURE: 'y'},
      writeAlerts: async() => {},
      dbHelpers: {lookupClientByAccountAndUsername: async(acct, user) => clients(user)}
    }}
  };
  return new Promise((resolve) => {
    const res = {send: (status) => resolve({status, calls, logs, req})};
    digestChallenge(req, res, () => resolve({status: 'next', calls, logs, req}));
  });
}

const studioClient = (user) => (user === 'st-1' ?
  [{client_sid: 'c1', account_sid: 'acct', username: 'st-1', password: encrypt('pw'), is_active: 1}] : []);

test('client in the table authenticates without calling the webhook', async(t) => {
  const r = await run({username: 'st-1', password: 'pw', clients: studioClient, hook: true});
  t.equal(r.status, 'next', 'authenticated');
  t.equal(r.calls.hook, 0, 'webhook not called');
  t.equal(r.req.authorization.grant.status, 'ok');
});

test('unknown user on a webhook account still goes to the webhook', async(t) => {
  const r = await run({username: 'phone-1', password: 'x', clients: () => [], hook: true, hookStatus: 200});
  t.equal(r.status, 'next', 'webhook accepted it');
  t.equal(r.calls.hook, 1, 'webhook called once');
});

test('wrong password for a table client falls back to the webhook', async(t) => {
  const r = await run({username: 'st-1', password: 'wrong', clients: studioClient, hook: true, hookStatus: 200});
  t.equal(r.calls.hook, 1, 'webhook called');
  t.equal(r.status, 'next');
});

test('database error falls back to the webhook instead of throwing', async(t) => {
  const r = await run({username: 'st-1', password: 'pw', clients: () => undefined, hook: true, hookStatus: 200});
  t.equal(r.calls.hook, 1);
  t.equal(r.status, 'next');
});

test('no webhook: table is authoritative (unchanged)', async(t) => {
  const ok = await run({username: 'st-1', password: 'pw', clients: studioClient});
  t.equal(ok.status, 'next');
  const bad = await run({username: 'st-1', password: 'wrong', clients: studioClient});
  t.equal(bad.status, 403);
  t.equal(bad.calls.hook, 0);
});

test('webhook failure is logged with the real error, not "{}"', async(t) => {
  const r = await run({username: 'phone-1', password: 'x', clients: () => [], hook: true, hookStatus: 500});
  t.equal(r.status, 500);
  const line = r.logs.find((a) => a[1] === 'Error from calling auth callback');
  t.ok(line, 'logged with a message');
  t.ok(line[0].err instanceof Error && /auth callback/.test(line[0].err.message), 'err object carried');
  t.equal(line[0].statusCode, 500);
});
