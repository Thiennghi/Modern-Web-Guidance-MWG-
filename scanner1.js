// SecureScan engine: URL, message (phishing) and code analysis. Pure functions, no DOM, no network.
(function () {
  'use strict';

  // MAX_LEN caps input size so a huge paste cannot freeze the browser.
  var MAX_LEN = 20000;

  // Helpers: lineOf turns a character position into a line number;
  // snippet returns the whole line (max 120 chars) to show as evidence.
  function lineOf(text, idx) { return text.slice(0, idx).split('\n').length; }
  function snippet(text, idx) {
    var s = text.lastIndexOf('\n', idx - 1) + 1, e = text.indexOf('\n', idx);
    return text.slice(s, e < 0 ? undefined : e).trim().slice(0, 120);
  }

  // The scanner is intentionally offline and heuristic-based; findings need human review.
  // ---------- Code rules ----------
  // CODE RULES. Each rule has: id, re (regex that finds the problem), title, risk,
  // why (why it matters) and fix (how to solve it). "mask: true" hides the matched
  // text in the report so secrets are never displayed.
  var CODE_RULES = [
    { id: 'MWG-001', re: /\beval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['"`]/g, title: 'Dynamic code execution', risk: 'High',
      why: 'Code built from strings runs with full page privileges, so injected input becomes attacker code.',
      fix: 'Remove eval/new Function. Use JSON.parse for data and pass functions (not strings) to timers.' },
    { id: 'MWG-002', re: /\.(?:innerHTML|outerHTML)\s*(?:\+?=)|insertAdjacentHTML\s*\(|\$\([^)]*\)\.html\s*\(/g, title: 'Unsafe HTML injection (XSS)', risk: 'High',
      why: 'Writing untrusted text as HTML lets attackers run scripts in your users\' sessions.',
      fix: 'Use textContent or createElement. If HTML is required, sanitise it with DOMPurify.' },
    { id: 'MWG-003', re: /document\.write(?:ln)?\s*\(/g, title: 'document.write()', risk: 'Medium',
      why: 'It can overwrite the page and is a common XSS sink.', fix: 'Build nodes with createElement/appendChild.' },
    { id: 'MWG-004', re: /console\.(?:log|debug)\s*\(/g, title: 'Debug output left in code', risk: 'Low',
      why: 'Logs can leak internal data to anyone with dev tools open.', fix: 'Remove debug logging before deployment.' },
    { id: 'MWG-005', re: /(?:pass(?:word|wd)?|secret|api[_-]?key|token|auth)\w*\s*[:=]\s*['"][^'"\s]{4,}['"]|AKIA[0-9A-Z]{16}|gh[pous]_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/gi,
      title: 'Hard-coded credential', risk: 'High', mask: true,
      why: 'Secrets in source code leak through repositories and browsers.',
      fix: 'Move secrets to server-side environment variables and rotate the exposed value.' },
    { id: 'MWG-006', re: /\bhttp:\/\/(?!localhost|127\.0\.0\.1)[^\s'"<>)]+/gi, title: 'Insecure HTTP link', risk: 'Medium',
      why: 'Plain HTTP can be read or modified by anyone on the network.', fix: 'Use https:// and add an HSTS header.' },
    { id: 'MWG-007', re: /\bon(?:click|load|error|mouseover|submit|focus)\s*=\s*['"]/gi, title: 'Inline event handler', risk: 'Medium',
      why: 'Inline handlers force you to weaken your Content Security Policy.', fix: 'Use addEventListener in an external script.' },
    { id: 'MWG-008', re: /target\s*=\s*['"]_blank['"](?![^>]*noopener)/gi, title: 'target="_blank" without rel="noopener"', risk: 'Low',
      why: 'The opened page can access window.opener and redirect your tab.', fix: 'Add rel="noopener noreferrer".' },
    { id: 'MWG-009', re: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*['"]\s*\+\s*\w+|(?:query|execute)\s*\(\s*`[^`]*\$\{/gi, title: 'SQL built from strings (injection)', risk: 'High',
      why: 'Concatenated user input can change the meaning of a query.', fix: 'Use parameterised queries / prepared statements.' },
    { id: 'MWG-010', re: /Math\.random\s*\(\)/g, title: 'Weak randomness', risk: 'Low',
      why: 'Math.random is predictable and unsafe for tokens or IDs.', fix: 'Use crypto.getRandomValues().' },
    { id: 'MWG-011', re: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*|postMessage\s*\([^)]*,\s*['"]\*['"]\s*\)|rejectUnauthorized\s*:\s*false/g, title: 'Over-permissive origin or TLS check', risk: 'Medium',
      why: 'Wildcards or disabled certificate checks let untrusted parties interact with your app.', fix: 'Allow only specific origins and keep certificate validation on.' },
    { id: 'MWG-012', re: /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"][^'"]*(?:token|session|jwt|password)/gi, title: 'Sensitive data in web storage', risk: 'Medium',
      why: 'Any XSS bug can read web storage.', fix: 'Use HttpOnly, Secure, SameSite cookies for session tokens.' }
  ];

  // ---------- URL analysis ----------
  // URL analysis lists: link shorteners, domain endings often abused by scams,
  // and brand names that scammers imitate.
  var SHORTENERS = /^(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rb\.gy|cutt\.ly)$/i;
  var RISKY_TLD = /\.(?:zip|mov|xyz|top|click|gq|tk|ml|cf|ga|work|loan|country)$/i;
  var BRANDS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook', 'instagram', 'bank', 'dhl', 'usps', 'fedex'];

  // analyzeUrl: parses a URL with the built-in URL class, then checks the scheme,
  // host, port, query string and path. Returns a list of findings.
  function analyzeUrl(raw, line) {
    var out = [], u, url = raw.trim();
    function f(id, title, risk, why, fix) { out.push({ ruleId: id, title: title, risk: risk, line: line, evidence: url.slice(0, 120), explanation: why, recommendation: fix }); }
    if (/^\s*(?:javascript|data|vbscript):/i.test(url)) {
      f('URL-001', 'Script or data URL', 'High', 'This scheme runs code or embeds content instead of loading a website.', 'Do not open it. Only allow http(s) links.');
      return out;
    }
    if (/^www\./i.test(url)) url = 'http://' + url;
    try { u = new URL(url); } catch (e) {
      f('URL-000', 'Not a valid URL', 'Low', 'The text could not be parsed as a web address.', 'Check the spelling and include https://.');
      return out;
    }
    var host = u.hostname.toLowerCase();
    if (u.protocol === 'http:') f('URL-002', 'No encryption (HTTP)', 'Medium', 'Data sent to this site can be read or changed in transit.', 'Prefer the https:// version; avoid entering any data.');
    if (u.username || u.password) f('URL-003', 'Credentials or "@" in the address', 'High', 'Text before "@" is ignored by the browser and is a classic way to disguise the real destination.', 'Treat as phishing. Check the host after the "@".');
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^\[.*\]$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) f('URL-004', 'IP address instead of a domain name', 'High', 'Legitimate services rarely use raw IPs for user-facing pages.', 'Verify the owner before visiting.');
    if (host.indexOf('xn--') > -1) f('URL-005', 'Punycode (look-alike characters)', 'High', 'Internationalised domains can imitate well-known brands.', 'Type the real address manually.');
    if (SHORTENERS.test(host)) f('URL-006', 'Link shortener', 'Medium', 'The final destination is hidden.', 'Expand the link with a trusted preview tool first.');
    if (RISKY_TLD.test(host)) f('URL-007', 'Domain ending often abused', 'Medium', 'Cheap or free endings are heavily used in scams.', 'Be cautious; confirm the sender independently.');
    if (host.split('.').length > 4) f('URL-008', 'Many subdomains', 'Medium', 'Long subdomain chains can hide the real domain at the end.', 'Read the host from right to left.');
    var labels = host.split('.'), root = labels.slice(-2).join('.');
    BRANDS.forEach(function (b) { if (host.indexOf(b) > -1 && root.indexOf(b) === -1) f('URL-009', 'Brand name used on another domain', 'High', 'Contains "' + b + '" but the real domain is ' + root + '.', 'Go to the brand\'s site directly instead.'); });
    if (u.port && u.port !== '80' && u.port !== '443') f('URL-010', 'Unusual port ' + u.port, 'Low', 'Non-standard ports are uncommon for public sites.', 'Confirm the service is expected.');
    if (/[?&](?:password|passwd|pwd|token|apikey|api_key|secret|session)=/i.test(u.search)) f('URL-011', 'Secret in the query string', 'High', 'URLs are stored in history, logs and Referer headers.', 'Send secrets in a POST body or header, never in the URL.');
    if (/%(?:2e|2f|5c|00)|\.\.\//i.test(u.pathname)) f('URL-012', 'Encoded path tricks', 'Medium', 'Encoded dots/slashes can indicate path traversal.', 'Validate and normalise paths on the server.');
    if (url.length > 200) f('URL-013', 'Very long URL', 'Low', 'Long URLs are often used to hide the real target.', 'Inspect it carefully.');
    return out;
  }

  // ---------- Message (phishing) analysis ----------
  // MESSAGE RULES: regexes for common phishing language (urgency, requests for
  // passwords or codes, prize or payment bait, threats, generic greetings).
  var MSG_RULES = [
    { id: 'MSG-001', re: /\b(?:urgent|immediately|within \d+ hours?|act now|last warning|final notice|expires? (?:today|soon))\b/i, title: 'Pressure or urgency', risk: 'Medium', why: 'Scammers rush you so you skip checks.', fix: 'Pause and verify through an official channel.' },
    { id: 'MSG-002', re: /\b(?:verify|confirm|update|re-?activate)\b[^.\n]{0,40}\b(?:account|password|identity|payment|card|bank)\b|\b(?:send|enter|provide)\b[^.\n]{0,30}\b(?:password|pin|otp|2fa|ssn|social security|card number)\b/i, title: 'Asks for credentials or personal data', risk: 'High', why: 'Real companies do not ask for passwords or codes by message.', fix: 'Never share it. Contact the company using its official site.' },
    { id: 'MSG-003', re: /\b(?:gift ?cards?|wire transfer|bitcoin|crypto|western union|zelle|you(?:'ve| have) won|lottery|prize|inheritance)\b/i, title: 'Unusual payment or prize bait', risk: 'High', why: 'Hard-to-reverse payments and "winnings" are hallmarks of fraud.', fix: 'Do not pay or reply.' },
    { id: 'MSG-004', re: /\b(?:suspended|locked|unusual (?:activity|sign-?in)|security alert|unauthori[sz]ed|legal action|arrest)\b/i, title: 'Threat or fake alert', risk: 'Medium', why: 'Fear is used to trigger a quick click.', fix: 'Open the service directly rather than using the message link.' },
    { id: 'MSG-005', re: /\b(?:dear (?:customer|user|member|client)|kindly)\b/i, title: 'Generic greeting', risk: 'Low', why: 'Mass messages rarely use your name.', fix: 'Treat with suspicion in combination with other signs.' }
  ];

  // ---------- Main scan ----------
  // scan: the main entry point. Validates the input, decides whether it is a URL
  // or text/code, runs the matching rules and returns { mode, findings }.
  function scan(input) {
    var text = String(input == null ? '' : input);
    if (!text.trim()) return { mode: 'empty', findings: [], error: 'Nothing to scan. Paste a URL, message or code.' };
    if (text.length > MAX_LEN) return { mode: 'empty', findings: [], error: 'Input is over ' + MAX_LEN + ' characters. Scan a smaller piece.' };

    var findings = [], single = text.trim();
    var isUrl = !/\s/.test(single) && /^(?:https?:\/\/|www\.|javascript:|data:|vbscript:)/i.test(single);
    var mode = isUrl ? 'URL' : 'Text / code';

    if (isUrl) findings = analyzeUrl(single, 1);
    else {
      CODE_RULES.forEach(function (r) {
        var re = new RegExp(r.re.source, r.re.flags), m, seen = 0;
        while ((m = re.exec(text)) && seen < 10) {
          seen++;
          findings.push({ ruleId: r.id, title: r.title, risk: r.risk, line: lineOf(text, m.index),
            evidence: r.mask ? '(hidden for safety)' : snippet(text, m.index), explanation: r.why, recommendation: r.fix });
          if (m[0].length === 0) re.lastIndex++;
        }
      });
      MSG_RULES.forEach(function (r) {
        var m = r.re.exec(text);
        if (m) findings.push({ ruleId: r.id, title: r.title, risk: r.risk, line: lineOf(text, m.index), evidence: snippet(text, m.index), explanation: r.why, recommendation: r.fix });
      });
      var seenUrls = {}, um, ure = /(?:https?:\/\/|www\.)[^\s'"<>)\]]+/gi;
      while ((um = ure.exec(text)) && Object.keys(seenUrls).length < 10) {
        if (seenUrls[um[0]]) continue;
        seenUrls[um[0]] = 1;
        analyzeUrl(um[0], lineOf(text, um.index)).forEach(function (x) {
          if (x.ruleId !== 'URL-002' || !findings.some(function (y) { return y.ruleId === 'MWG-006' && y.line === x.line; })) findings.push(x);
        });
      }
    }

    // Sort most severe first (then by line).
    var order = { High: 0, Medium: 1, Low: 2, Info: 3 };
    findings.sort(function (a, b) { return order[a.risk] - order[b.risk] || a.line - b.line; });
    return { mode: mode, findings: findings };
  }

  // ---------- Syntax checker (skips strings and comments) ----------
  // checkSyntax: walks the code one character at a time, skipping comments and
  // strings, and uses a stack to match ( [ { brackets. Line checks come afterwards.
  function checkSyntax(code) {
    var issues = [], stack = [], pairs = { ')': '(', ']': '[', '}': '{' };
    var i = 0, n = code.length, line = 1;
    while (i < n) {
      var c = code[i], d = code[i + 1];
      if (c === '\n') { line++; i++; continue; }
      if (c === '/' && d === '/') { while (i < n && code[i] !== '\n') i++; continue; }
      if (c === '/' && d === '*') {
        var sl = line; i += 2;
        while (i < n && !(code[i] === '*' && code[i + 1] === '/')) { if (code[i] === '\n') line++; i++; }
        if (i >= n) issues.push({ line: sl, level: 'Error', msg: 'Comment "/*" is never closed.' });
        i += 2; continue;
      }
      if (c === '"' || c === "'" || c === '`') {
        var q = c, s = line, closed = false; i++;
        while (i < n) {
          var x = code[i];
          if (x === '\\') { if (code[i + 1] === '\n') line++; i += 2; continue; }
          if (x === '\n') { if (q !== '`') break; line++; }
          else if (x === q) { closed = true; i++; break; }
          i++;
        }
        if (!closed) issues.push({ line: s, level: 'Error', msg: 'String starting with ' + q + ' is never closed.' });
        continue;
      }
      if ('([{'.indexOf(c) > -1) stack.push({ c: c, line: line });
      else if (')]}'.indexOf(c) > -1) {
        var t = stack.pop();
        if (!t) issues.push({ line: line, level: 'Error', msg: 'Unexpected "' + c + '" with no opening bracket.' });
        else if (t.c !== pairs[c]) issues.push({ line: line, level: 'Error', msg: '"' + c + '" does not match "' + t.c + '" opened on line ' + t.line + '.' });
      }
      i++;
    }
    stack.forEach(function (t) { issues.push({ line: t.line, level: 'Error', msg: '"' + t.c + '" is never closed.' }); });

    // Second pass, line by line: assignment inside if(), loose ==, missing
    // semicolons, duplicate let/const names, and use of var.
    var declared = {};
    code.split('\n').forEach(function (raw, k) {
      var ln = k + 1, t = raw.trim();
      if (!t || t.indexOf('//') === 0 || t.indexOf('*') === 0) return;
      if (/\bif\s*\([^()]*[^=!<>]=(?!=)[^()]*\)/.test(t)) issues.push({ line: ln, level: 'Warning', msg: 'Assignment "=" inside if(...). Did you mean "===" ?' });
      if (/[^=!]==[^=]/.test(t.replace(/(["'`]).*?\1/g, ''))) issues.push({ line: ln, level: 'Warning', msg: 'Loose equality "==". Prefer "===".' });
      if (/^(?:const|let|var|return)\b.*[^;{,(\[\s+\-*\/&|?:=]$/.test(t) && !/^(?:const|let|var)\s+\w+\s*$/.test(t)) issues.push({ line: ln, level: 'Warning', msg: 'Statement may be missing a semicolon.' });
      var m = /^(?:const|let)\s+([A-Za-z_$][\w$]*)/.exec(t);
      if (m) { if (declared[m[1]]) issues.push({ line: ln, level: 'Error', msg: '"' + m[1] + '" is already declared on line ' + declared[m[1]] + '.' }); else declared[m[1]] = ln; }
      if (/^var\b/.test(t)) issues.push({ line: ln, level: 'Warning', msg: '"var" is function-scoped. Prefer let or const.' });
    });
    issues.sort(function (a, b) { return a.line - b.line; });
    return issues.slice(0, 100);
  }

  // Expose only a frozen public API so other scripts cannot change the scanner.
  window.SecureScan = Object.freeze({ scan: scan, checkSyntax: checkSyntax, MAX_LEN: MAX_LEN });
})();

// =====================================================================
// SAMPLE INPUT BUTTONS ("Try an example:")
// What it does: adds a row of example buttons under the Vulnerability scan
// box and under the Syntax check box. Clicking one fills the box with a
// known sample and presses the existing Scan / Check button, so the result
// appears straight away. index.html, app1.js and style.css are not changed:
// this code only reuses their element ids (input-scan, btn-scan,
// input-syntax, btn-syntax) and the existing .row, .hint and .chip styles.
// To add a sample: add one { label, text } entry to the lists below.
// Everything is built with textContent, so the strict CSP still holds.
// =====================================================================
(function () {
  'use strict';

  // Samples for the Vulnerability scan tab.
  var SCAN_SAMPLES = [
    { label: 'Suspicious URL', text: 'http://secure-paypal.login-verify.xyz@192.168.4.7:8080/signin?password=abc123' },
    { label: 'Phishing message', text: 'Dear customer,\nURGENT: your account has been suspended. Verify your password within 24 hours at http://bit.ly/3xYz or you will face legal action.' },
    { label: 'Vulnerable code', text: 'const apiKey = "sk_live_12345678";\nfunction show(name) {\n  document.getElementById("out").innerHTML = "Hi " + name;\n}\neval(userInput);\nfetch("http://api.example.com/data");' },
    { label: 'Safe URL', text: 'https://www.wikipedia.org/' },
    { label: 'Short link', text: 'https://bit.ly/3xYz' },
    { label: 'Brand look-alike', text: 'https://paypal.com.account-check.top/login' },
    { label: 'Look-alike characters', text: 'http://xn--pypal-4ve.com/login' },
    { label: 'Script URL', text: 'javascript:alert(document.cookie)' },
    { label: 'Prize scam', text: 'Congratulations! You have won a prize. Send your card number to claim your gift card today.' },
    { label: 'Friendly message', text: 'Hi Sam, are we still meeting for lunch at noon tomorrow? See you at the usual place.' },
    { label: 'SQL injection code', text: 'const q = "SELECT * FROM users WHERE id = \'" + userId + "\'";\ndb.query(q);' }
  ];

  // Samples for the Syntax check tab.
  var SYNTAX_SAMPLES = [
    { label: 'Unclosed bracket', text: 'function add(a, b) {\n  return a + b;\n' },
    { label: 'Unclosed string', text: 'const message = "hello world;\nconsole.log(message);' },
    { label: 'Common mistakes', text: 'var count = 1\nif (count = 2) {\n  console.log(count == 2);\n}' },
    { label: 'Clean code', text: 'const total = 1 + 2;\nconsole.log(total);' },
    { label: 'Mismatched brackets', text: 'if (x > 1) {\n  console.log([1, 2);\n}' },
    { label: 'Duplicate variable', text: 'let a = 1;\nlet a = 2;' }
  ];

  // addSamples: puts a "Try an example:" row right under a textarea. Each button
  // fills the textarea, then clicks the existing action button.
  function addSamples(inputId, buttonId, samples) {
    var box = document.getElementById(inputId);
    var action = document.getElementById(buttonId);
    if (!box || !action || box.parentNode.querySelector('[data-samples="' + inputId + '"]')) return;

    var row = document.createElement('div');
    row.className = 'row';
    row.setAttribute('data-samples', inputId);

    var hint = document.createElement('span');
    hint.className = 'hint';
    hint.textContent = 'Try an example:';
    row.appendChild(hint);

    samples.forEach(function (s) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'chip';
      b.textContent = s.label;
      b.addEventListener('click', function () {
        box.value = s.text;
        action.click();
      });
      row.appendChild(b);
    });

    box.parentNode.insertBefore(row, box.nextSibling);
  }

  function init() {
    addSamples('input-scan', 'btn-scan', SCAN_SAMPLES);
    addSamples('input-syntax', 'btn-syntax', SYNTAX_SAMPLES);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

// =====================================================================
// SCAN HISTORY (fills the "Scan history" table in index.html)
// What it does: every time the user presses Scan (or clicks an example
// button, which presses Scan) or Check code, one row is added to the table:
// date/time, type, a short preview of the input, number of findings and
// the highest risk. Newest rows are on top and the last 20 are kept.
// Rows stay in the table, even after a page refresh, until the user clicks
// "Clear history"; then the table is emptied and ready for new input.
// Privacy: previews are shortened to 60 characters, and if the input looks
// like it contains a secret (password, API key, "@" credentials in a URL)
// the preview is replaced with a note instead of showing it.
// Storage: localStorage in this browser only; nothing is sent anywhere.
// If storage is blocked, the history still works until the page is closed.
// index.html, app1.js and style.css are not changed: this code only uses
// the existing ids btn-scan, btn-syntax, input-scan, input-syntax,
// history-body and btn-clear-history. Everything is built with
// textContent, so pasted input can never inject HTML.
// =====================================================================
(function () {
  'use strict';

  var KEY = 'securescan.history.v1';   // storage key
  var MAX_ROWS = 20;                   // keep only the newest 20 rows
  var PREVIEW_LEN = 60;                // characters of input shown in the table
  var entries = [];                    // newest first: { time, type, preview, count, risk }

  // load: read saved rows. Any problem (blocked storage, bad data) gives an empty list.
  function load() {
    try {
      var list = JSON.parse(localStorage.getItem(KEY) || '[]');
      if (!Array.isArray(list)) return [];
      return list.slice(0, MAX_ROWS).map(function (e) {
        return { time: String(e.time), type: String(e.type), preview: String(e.preview), count: Number(e.count) || 0, risk: String(e.risk) };
      });
    } catch (err) { return []; }
  }

  // save: write the rows back. If storage is blocked we simply keep them in memory.
  function save() {
    try { localStorage.setItem(KEY, JSON.stringify(entries)); } catch (err) { /* ignore */ }
  }

  // looksSecret: true when the scan found a password, key or "@" credentials,
  // so the table never repeats a secret back to the screen or into storage.
  function looksSecret(text) {
    var res = window.SecureScan.scan(text);
    return !res.error && res.findings.some(function (f) {
      return f.ruleId === 'MWG-005' || f.ruleId === 'URL-011' || f.ruleId === 'URL-003';
    });
  }

  // makePreview: one short line of the input, or a note if it may hold a secret.
  function makePreview(text) {
    if (looksSecret(text)) return '(hidden: may contain a secret)';
    var one = text.replace(/\s+/g, ' ').trim();
    return one.length > PREVIEW_LEN ? one.slice(0, PREVIEW_LEN) + '...' : one;
  }

  // cell: builds a <td> using textContent only.
  function cell(text, span) {
    var td = document.createElement('td');
    td.textContent = text;
    if (span) td.colSpan = span;
    return td;
  }

  // render: redraws the table body from the saved rows.
  function render() {
    var body = document.getElementById('history-body');
    if (!body) return;
    while (body.firstChild) body.removeChild(body.firstChild);
    if (!entries.length) {
      var empty = document.createElement('tr');
      empty.appendChild(cell('No scans yet.', 5));
      body.appendChild(empty);
      return;
    }
    entries.forEach(function (e) {
      var tr = document.createElement('tr');
      tr.appendChild(cell(e.time));
      tr.appendChild(cell(e.type));
      tr.appendChild(cell(e.preview));
      tr.appendChild(cell(String(e.count)));
      tr.appendChild(cell(e.risk));
      body.appendChild(tr);
    });
  }

  // record: adds a new row at the top, trims the list, saves and redraws.
  function record(type, text, count, risk) {
    entries.unshift({ time: new Date().toLocaleString(), type: type, preview: makePreview(text), count: count, risk: risk });
    entries = entries.slice(0, MAX_ROWS);
    save();
    render();
  }

  // onScan: runs when Scan is pressed. Empty or oversized input is skipped
  // because app1.js shows an error for it instead of a result.
  function onScan() {
    var text = document.getElementById('input-scan').value;
    var res = window.SecureScan.scan(text);
    if (res.error) return;
    record(res.mode, text, res.findings.length, res.findings.length ? res.findings[0].risk : 'None');
  }

  // onSyntax: runs when Check code is pressed. Highest "risk" is Error,
  // then Warning, otherwise None.
  function onSyntax() {
    var code = document.getElementById('input-syntax').value;
    if (!code.trim() || code.length > window.SecureScan.MAX_LEN) return;
    var issues = window.SecureScan.checkSyntax(code);
    var worst = issues.some(function (i) { return i.level === 'Error'; }) ? 'Error' : issues.length ? 'Warning' : 'None';
    record('Syntax check', code, issues.length, worst);
  }

  // clearHistory: empties the saved rows and the table, ready for new input.
  function clearHistory() {
    entries = [];
    try { localStorage.removeItem(KEY); } catch (err) { /* ignore */ }
    render();
  }

  // init: load saved rows, draw the table, and attach the three buttons.
  function init() {
    entries = load();
    render();
    var a = document.getElementById('btn-scan');
    var b = document.getElementById('btn-syntax');
    var c = document.getElementById('btn-clear-history');
    if (a) a.addEventListener('click', onScan);
    if (b) b.addEventListener('click', onSyntax);
    if (c) c.addEventListener('click', clearHistory);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
