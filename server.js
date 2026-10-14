
'use strict';

const express = require('express');
const dns2 = require('dns2');
const net = require('node:net');

const app = express();
const PORT = Number(process.env.PORT || 10000);

app.disable('x-powered-by');
app.use(express.json({ limit: '8kb' }));

const Packet = dns2.Packet;

// Only map domains you own or are authorized to redirect.
// Use real IP addresses belonging to your revival servers.
const RECORDS = {
  'revival.example.com': {
    A: ['192.0.2.10'],
    AAAA: [],
    TTL: 60
  },
  'community.example.com': {
    A: ['192.0.2.10'],
    AAAA: [],
    TTL: 60
  }
};

function findRecord(name, type) {
  const key = name.toLowerCase().replace(/\.$/, '');
  const record = RECORDS[key];

  if (!record) return null;

  const addresses = record[type] || [];
  return {
    addresses,
    ttl: record.TTL || 60
  };
}

function answerDNS(request) {
  const response = Packet.createResponseFromRequest(request);
  const question = request.questions[0];

  if (!question) {
    response.header.rcode = Packet.RCODE.FORMERR;
    return response;
  }

  const name = question.name.toLowerCase().replace(/\.$/, '');
  const type = question.type;

  // This is a controlled mapping service, not a recursive resolver.
  const record = findRecord(name, Packet.TYPE.A === type
    ? 'A'
    : Packet.TYPE.AAAA === type
      ? 'AAAA'
      : '');

  if (!record) {
    response.header.rcode = Packet.RCODE.REFUSED;
    return response;
  }

  if (type === Packet.TYPE.A) {
    for (const address of record.addresses) {
      if (!net.isIPv4(address)) continue;

      response.answers.push({
        name: question.name,
        type: Packet.TYPE.A,
        class: Packet.CLASS.IN,
        ttl: record.ttl,
        address
      });
    }
  } else if (type === Packet.TYPE.AAAA) {
    for (const address of record.addresses) {
      if (!net.isIPv6(address)) continue;

      response.answers.push({
        name: question.name,
        type: Packet.TYPE.AAAA,
        class: Packet.CLASS.IN,
        ttl: record.ttl,
        address
      });
    }
  } else {
    response.header.rcode = Packet.RCODE.REFUSED;
  }

  return response;
}

app.get('/', (req, res) => {
  res.json({
    name: 'Universal Revival DNS',
    protocol: 'DNS-over-HTTPS',
    status: 'online',
    endpoints: ['/health', '/dns-query']
  });
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// RFC 8484-style DNS-over-HTTPS endpoint.
// Accepts DNS wire-format messages encoded as base64url.
app.get('/dns-query', (req, res) => {
  if (typeof req.query.dns !== 'string') {
    return res.status(400).send('Missing dns parameter');
  }

  let message;

  try {
    message = Buffer.from(req.query.dns, 'base64url');

    if (message.length < 12 || message.length > 4096) {
      return res.status(400).send('Invalid DNS message size');
    }
  } catch {
    return res.status(400).send('Invalid DNS message');
  }

  try {
    const request = Packet.parse(message);
    const response = answerDNS(request);
    const output = Packet.toBuffer(response);

    res.setHeader('Content-Type', 'application/dns-message');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(output);
  } catch {
    return res.status(400).send('Invalid DNS packet');
  }
});

// Do not expose an unrestricted DNS-over-HTTPS proxy.
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Universal Revival DoH listening on port ${PORT}`);
});
