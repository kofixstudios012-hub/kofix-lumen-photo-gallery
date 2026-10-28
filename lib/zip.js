'use strict';
// Streams a ZIP (stored, no compression - photos are already compressed) to an HTTP response.
const zlib = require('node:zlib');
const { once } = require('node:events');

function dos(d) {
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

// entries: [{ name, read: async () => Buffer }]
async function writeZip(res, entries) {
  const { time, date } = dos(new Date());
  let offset = 0;
  const w = async (b) => { offset += b.length; if (!res.write(b)) await once(res, 'drain'); };
  const central = [];

  for (const e of entries) {
    const data = await e.read();
    const name = Buffer.from(e.name, 'utf8');
    const crc = zlib.crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0808, 6);
    lh.writeUInt16LE(0, 8); lh.writeUInt16LE(time, 10); lh.writeUInt16LE(date, 12);
    lh.writeUInt16LE(name.length, 26);
    const start = offset;
    await w(lh); await w(name); await w(data);
    const dd = Buffer.alloc(16);
    dd.writeUInt32LE(0x08074b50, 0); dd.writeUInt32LE(crc, 4); dd.writeUInt32LE(data.length, 8); dd.writeUInt32LE(data.length, 12);
    await w(dd);
    central.push({ name, crc, size: data.length, start });
  }

  const cdStart = offset;
  for (const c of central) {
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0808, 8);
    ch.writeUInt16LE(0, 10); ch.writeUInt16LE(time, 12); ch.writeUInt16LE(date, 14);
    ch.writeUInt32LE(c.crc, 16); ch.writeUInt32LE(c.size, 20); ch.writeUInt32LE(c.size, 24);
    ch.writeUInt16LE(c.name.length, 28); ch.writeUInt32LE(c.start, 42);
    await w(ch); await w(c.name);
  }
  const cdSize = offset - cdStart;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(central.length, 8); end.writeUInt16LE(central.length, 10);
  end.writeUInt32LE(cdSize, 12); end.writeUInt32LE(cdStart, 16);
  await w(end);
  res.end();
}

module.exports = { writeZip };
