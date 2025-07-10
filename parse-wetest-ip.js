const cheerio = require('cheerio');
const fetch = require('node-fetch').default;
const { HttpsProxyAgent } = require('https-proxy-agent');

function getFetchOptions() {
  const proxy = process.env.https_proxy || process.env.HTTPS_PROXY;
  if (proxy) {
    return { agent: new HttpsProxyAgent(proxy) };
  }
  return {};
}

async function fetchIPList() {
  const url = 'https://www.wetest.vip/page/edgeone/address_v4.html';
  const res = await fetch(url, getFetchOptions());
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const html = await res.text();
  const $ = cheerio.load(html);
  const rows = $('div.cname-table-wrapper table tbody tr');
  const data = [];
  rows.each((i, tr) => {
    const cells = $(tr).find('td');
    const entry = {
      line: $(cells[0]).text().trim(),
      ip: $(cells[1]).text().trim(),
      bandwidth: $(cells[2]).text().trim(),
      speed: $(cells[3]).text().trim(),
      latency: $(cells[4]).text().trim(),
      region: $(cells[5]).text().trim(),
      updated: $(cells[6]).text().trim(),
    };
    data.push(entry);
  });
  return data;
}

async function main() {
  try {
    const list = await fetchIPList();
    console.log(JSON.stringify(list, null, 2));
  } catch (err) {
    console.error('Failed to fetch IP list:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
