const nonce = require('nonce')();
const debug = require('debug')('jambonz:sbc-registrar');
const qs = require('qs');
const crypto = require('crypto');
const { decrypt } = require('./utils');
const toBase64 = (str) => Buffer.from(str || '', 'utf8').toString('base64');

function basicAuth(username, password) {
  if (!username || !password) return {};
  const creds = `${username}:${password || ''}`;
  const header = `Basic ${toBase64(creds)}`;
  return {Authorization: header};
}

function respondChallenge(req, res) {
  const nonceValue = nonce();
  const {realm} = req.locals;
  const headers = {
    'WWW-Authenticate': `Digest realm="${realm}", algorithm=MD5, qop="auth", nonce="${nonceValue}"`
  };
  debug('sending a 401 challenge');
  res.send(401, {headers});
}

function parseAuthHeader(hdrValue) {
  const pieces = { scheme: 'digest'} ;
  ['username', 'realm', 'nonce', 'uri', 'algorithm', 'response', 'qop', 'nc', 'cnonce', 'opaque']
    .forEach((tok) => {
      const re = new RegExp(`[,\\s]{1}${tok}="?(.+?)[",]`) ;
      const arr = re.exec(hdrValue) ;
      if (arr) {
        pieces[tok] = arr[1];
        if (pieces[tok] && pieces[tok] === '"') pieces[tok] = '';
      }
    }) ;

  pieces.algorithm = pieces.algorithm || 'MD5' ;

  // this is kind of lame...nc= (or qop=) at the end fails the regex above,
  // should figure out how to fix that
  if (!pieces.nc && /nc=/.test(hdrValue)) {
    const arr = /nc=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.nc = arr[1];
    }
  }
  if (!pieces.qop && /qop=/.test(hdrValue)) {
    const arr = /qop=(.*)$/.exec(hdrValue) ;
    if (arr) {
      pieces.qop = arr[1];
    }
  }

  // check mandatory fields
  ['username', 'realm', 'nonce', 'uri', 'response'].forEach((tok) => {
    if (!pieces[tok]) throw new Error(`missing authorization component: ${tok}`);
  }) ;
  debug(`parsed header: ${JSON.stringify(pieces)}`);
  return pieces ;
}

function computeSignature(payload, timestamp, secret) {
  const data = 'string' === payload ?
    payload :
    JSON.stringify(payload);
  return crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${data}`, 'utf8')
    .digest('hex');
}

function generateSigHeader(payload, secret) {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = computeSignature(payload, timestamp, secret);
  const scheme = 'v1';
  return {
    'Jambonz-Signature': `t=${timestamp},${scheme}=${signature}`
  };
}

async function httpAuthenticate(logger, data, url, hook_method, secret, username, password, req) {
  const {AlertType, writeAlerts} = req.srf.locals;
  const {account_sid} = req.locals;
  try {
    let uri = url;
    let body;
    const method = hook_method ? hook_method.toUpperCase() : 'POST';
    if ('GET' === method) {
      const str = qs.stringify(data);
      uri = `${uri}?${str}`;
    } else {
      body = data;
    }
    const headers = {
      'Content-Type': 'application/json',
      ...(username &&
        password &&
        basicAuth(username, password)),
      ...(secret && generateSigHeader(body || 'null', secret)),
      ...(process.env.JAMBONES_HTTP_USER_AGENT_HEADER && {'user-agent' : process.env.JAMBONES_HTTP_USER_AGENT_HEADER}),
    };
    const response = await fetch(uri, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });

    if (response.status !== 200) {
      const err = new Error(`Error from auth callback: ${response.statusText}`);
      err.statusCode = response.status;
      err.hook = uri;
      err.code = 'StatusError';
      throw err;
    }
    const json = await response.json();
    return {
      ...json,
      statusCode: 200
    };
  } catch (err) {
    logger.info(JSON.stringify(err), `Error from calling auth callback: ${err}`);
    let opts = { account_sid };
    if (err.code === 'StatusError' || (err.cause && err.cause.name === 'StatusError')) {
      opts = { ...opts, alert_type: AlertType.WEBHOOK_STATUS_FAILURE, url: err.hook || url, status: err.statusCode };
    }
    else if (err.cause && err.cause.code === 'ECONNREFUSED') {
      opts = { ...opts, alert_type: AlertType.WEBHOOK_CONNECTION_FAILURE, url: err.hook || url };
    }
    else if (err.cause && err.cause.code === 'ENOTFOUND') {
      opts = { ...opts, alert_type: AlertType.WEBHOOK_CONNECTION_FAILURE, url: err.hook || url };
    }
    else if (err instanceof TypeError) {
      opts = { ...opts, alert_type: AlertType.WEBHOOK_CONNECTION_FAILURE, url: url };
    }
    if (opts.alert_type) {
      try {
        await writeAlerts(opts);
      } catch (err) {
        logger.error({ err, opts }, 'Error writing alert');
      }
    }

    return {
      status: 'failed',
      statusCode: err.statusCode || 500
    };
  }
}

function calculateResponse({username, realm, method, nonce, uri, nc, cnonce, qop}, password) {
  const ha1 = crypto.createHash('md5');
  ha1.update([username, realm, password].join(':'));
  const ha2 = crypto.createHash('md5');
  ha2.update([method, uri].join(':'));

  // Generate response hash
  const response = crypto.createHash('md5');
  const responseParams = [
    ha1.digest('hex'),
    nonce
  ];

  if (cnonce) {
    responseParams.push(nc);
    responseParams.push(cnonce);
  }

  if (qop) {
    responseParams.push(qop);
  }
  responseParams.push(ha2.digest('hex'));
  response.update(responseParams.join(':'));

  return response.digest('hex');
}

async function clientAuthentication(logger, data, req) {
  const {username, response} = data;
  const {account_sid} = req.locals;
  const {lookupClientByAccountAndUsername} = req.srf.locals.dbHelpers;

  const clients = await lookupClientByAccountAndUsername(account_sid, username);
  if (clients.length) {
    // Only take the first result.
    const client = clients[0];
    client.password = decrypt(client.password);
    if (client.is_active && calculateResponse(data, client.password) === response) {
      // eslint-disable-next-line no-unused-vars
      const {client_sid, account_sid, is_active, username, password, ...settings} = client;
      return {
        status: 'ok',
        statusCode: 200,
        ...settings
      };
    }
  }
  return {
    status: 'failed',
    statusCode: 200
  };
}

const digestChallenge = async(req, res, next) => {
  const {logger} = req.locals;
  const {stats} = req.srf.locals;
  const {
    account_sid,
    registration_hook_url,
    registration_hook_method,
    registration_hook_username,
    registration_hook_password,
    webhook_secret
  } = req.locals;
  // Cannot detect account, reject register request
  try {
    if (!account_sid) {
      return res.send(403, {
        headers: {
          'X-Reason': 'Unknown or invalid realm'
        }
      });
    }

    // challenge requests without credentials
    if (!req.has('Authorization')) return respondChallenge(req, res);

    const pieces = parseAuthHeader(req.get('Authorization'));
    const expires = req.registration ? req.registration.expires : null;
    const data = {
      source_address: req.source_address,
      source_port: req.source_port,
      method: req.method,
      ...('POST' === registration_hook_method && {headers: req.headers}),
      expires,
      ...pieces
    };
    logger.debug(data, 'Authorization data');

    const startAt = process.hrtime();
    // Authenticate via HTTP server
    let authResult;
    if (registration_hook_url) {
      authResult = await httpAuthenticate(
        logger,
        data,
        registration_hook_url,
        registration_hook_method,
        webhook_secret,
        registration_hook_username,
        registration_hook_password,
        req
      );
    } else {
      // Check if client is available in DB.
      authResult = await clientAuthentication(logger, data, req);
    }
    const diff = process.hrtime(startAt);
    const rtt = diff[0] * 1e3 + diff[1] * 1e-6;

    if (authResult.statusCode !== 200) {
      // Error happens
      return res.send(authResult.statusCode);
    } else if (authResult.status.toLowerCase() !== 'ok') {
      // Authentication failed
      res.send(403, {headers: {
        'X-Reason': authResult.blacklist === true ?
          `detected potential spammer from ${req.source_address}:${req.source_port}` :
          'Invalid credentials',
        ...(authResult.headers || {})
      }});
      stats.histogram('app.hook.response_time', rtt.toFixed(0), ['hook_type:auth', `status:${403}`]);
      return;
    } else {
      // Authentication success
      req.authorization = {
        challengeResponse: pieces,
        grant: authResult
      };
      stats.histogram('app.hook.response_time', rtt.toFixed(0), ['hook_type:auth', `status:${200}`]);
    }
    next();
  } catch (err) {
    logger.error(`Error ${err}, rejecting with 403`);
    return next(err);
  }
};

module.exports = digestChallenge;
