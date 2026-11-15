// SecureScan UI. All output is built with textContent / createElement, never innerHTML.
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  // Remembers the latest scan result so the assistant can explain it.
  var lastScan = null;

  // Sample inputs for the example buttons (data-ex in index.html picks one).
  var EXAMPLES = {
    url: 'http://secure-paypal.login-verify.xyz@192.168.4.7:8080/signin?password=abc123',
    msg: 'Dear customer,\nURGENT: your account has been suspended. Verify your password within 24 hours at http://bit.ly/3xYz or you will face legal action.',
    code: 'const apiKey = "sk_live_12345678";\nfunction show(name) {\n  document.getElementById("out").innerHTML = "Hi " + name;\n}\neval(userInput);\nfetch("http://api.example.com/data");'
  };

  // Safe DOM helpers. el() builds an element and sets text with textContent
  // (never innerHTML), so pasted input can never inject HTML. clear() empties a
  // node and field() adds a "Label: value" line to a box.
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function riskClass(r) { return String(r).toLowerCase(); }
  function field(parent, label, value, asCode) {
    var p = el('p');
    p.appendChild(el('strong', null, label + ': '));
    p.appendChild(asCode ? el('span', 'ev', value) : document.createTextNode(value));
    parent.appendChild(p);
  }

  // ---------- Tabs ----------
  // Tabs: mark the chosen tab as selected and show only its panel.
  function showTab(name) {
    document.querySelectorAll('.tabs [role=tab]').forEach(function (b) {
      b.setAttribute('aria-selected', String(b.dataset.tab === name));
    });
    ['scan', 'syntax', 'ai'].forEach(function (t) { $('panel-' + t).hidden = (t !== name); });
  }

  // ---------- Scan ----------
  // runScan: reads the textarea, calls the scanner, then builds the summary banner
  // and one box per finding.
  function runScan() {
    var out = $('out-scan');
    clear(out);
    var res = window.SecureScan.scan($('input-scan').value);
    if (res.error) { out.appendChild(el('p', 'err', res.error)); return; }
    lastScan = res;

    var worst = res.findings.length ? riskClass(res.findings[0].risk) : 'none';
    var v = el('div', 'verdict');
    var vt = el('div');
    vt.appendChild(el('p', null, 'Detected as: ' + res.mode));
    vt.appendChild(el('p', null, res.findings.length ? res.findings.length + ' issue(s) found. Highest risk: ' + res.findings[0].risk + '.' : 'No known issues found.'));
    v.appendChild(vt);
    out.appendChild(v);

    if (!res.findings.length) {
      var ok = el('div', 'finding none');
      ok.appendChild(el('h3', null, 'No issues detected'));
      ok.appendChild(el('p', null, 'This only means none of the built-in rules matched. It is not proof that the input is safe.'));
      out.appendChild(ok);
      return;
    }
    res.findings.forEach(function (f) {
      var box = el('div', 'finding ' + riskClass(f.risk));
      var h = el('h3');
      h.appendChild(el('span', 'badge ' + riskClass(f.risk), f.risk + ' '));
      h.appendChild(document.createTextNode(f.title));
      box.appendChild(h);
      field(box, 'Rule', f.ruleId + ' (line ' + f.line + ')');
      field(box, 'Found', f.evidence, true);
      field(box, 'Why it matters', f.explanation);
      field(box, 'How to fix', f.recommendation);
      out.appendChild(box);
    });
  }

  // ---------- Syntax ----------
  // runSyntax: validates the input, runs the syntax checker and lists each
  // problem with its line number.
  function runSyntax() {
    var out = $('out-syntax');
    clear(out);
    var code = $('input-syntax').value;
    if (!code.trim()) { out.appendChild(el('p', 'err', 'Paste some JavaScript first.')); return; }
    if (code.length > window.SecureScan.MAX_LEN) { out.appendChild(el('p', 'err', 'Input is too large.')); return; }
    var issues = window.SecureScan.checkSyntax(code);
    if (!issues.length) { out.appendChild(el('p', 'ok', 'No syntax problems found.')); return; }
    issues.forEach(function (i) {
      var box = el('div', 'finding ' + (i.level === 'Error' ? 'high' : 'medium'));
      var h = el('h3');
      h.appendChild(el('span', 'badge ' + (i.level === 'Error' ? 'high' : 'medium'), i.level + ' '));
      h.appendChild(document.createTextNode('Line ' + i.line));
      box.appendChild(h);
      box.appendChild(el('p', null, i.msg));
      out.appendChild(box);
    });
  }

  // ---------- Local assistant ----------
  // Assistant knowledge base: if the question contains any word in k, the
  // matching answer a is returned.
  var KB = [
    { k: ['xss', 'cross-site', 'innerhtml'], a: 'XSS happens when untrusted text is rendered as HTML or script. Fixes: use textContent instead of innerHTML, sanitise any required HTML with DOMPurify, encode output for its context, and ship a strict Content Security Policy.' },
    { k: ['phish', 'scam', 'suspicious message', 'email'], a: 'Phishing signs: urgency or threats, requests for passwords/codes/payment, generic greetings, mismatched sender or link domains, and look-alike URLs. Do not click; open the real site yourself or call the company using a number from its official site.' },
    { k: ['csp', 'content security'], a: 'A Content Security Policy limits where scripts and styles can load from. Start with default-src \'none\' and add only what you need. Avoid \'unsafe-inline\'. Send it as an HTTP header so frame-ancestors also works.' },
    { k: ['sql', 'injection'], a: 'SQL injection: never build queries by joining strings. Use parameterised queries or an ORM, give the database account least privilege, and validate input types.' },
    { k: ['https', 'http', 'tls', 'hsts'], a: 'Use HTTPS everywhere, redirect HTTP to HTTPS, and add Strict-Transport-Security so browsers refuse plain HTTP.' },
    { k: ['password', 'secret', 'credential', 'api key', 'token'], a: 'Never put secrets in front-end code or URLs. Keep them in server-side environment variables or a secrets manager, rotate anything that leaked, and store session tokens in HttpOnly, Secure, SameSite cookies.' },
    { k: ['csrf'], a: 'CSRF tricks a logged-in browser into sending requests. Use SameSite cookies, anti-CSRF tokens on state-changing requests, and check the Origin header.' },
    { k: ['eval'], a: 'eval() and new Function() run strings as code. Replace them with JSON.parse, lookup tables, or real functions.' },
    { k: ['url', 'link', 'domain'], a: 'To judge a URL, read the host from right to left: the last two labels are the real domain. Be wary of IP addresses, "@" signs, xn-- (look-alike) domains, shorteners and brand names on unrelated domains. Use the Vulnerability scan tab to check one.' },
    { k: ['hello', 'hi', 'help'], a: 'Hi! Paste something in the Vulnerability scan tab, then ask me to "explain my last scan". I can also answer questions about XSS, phishing, CSP, SQL injection, HTTPS, secrets and CSRF.' }
  ];

  // explainLast: summarises the last scan with the top 5 fixes, most severe first.
  function explainLast() {
    if (!lastScan || lastScan.error) return 'Run a scan first, then ask me again.';
    if (!lastScan.findings.length) return 'Your last scan (' + lastScan.mode + ') matched no rules. Keep in mind scanners miss things: review manually and keep dependencies updated.';
    var lines = ['Last scan: ' + lastScan.mode + '. Fix in this order:'];
    lastScan.findings.slice(0, 5).forEach(function (f, i) {
      lines.push((i + 1) + '. ' + f.title + ' (' + f.risk + ', line ' + f.line + '): ' + f.recommendation);
    });
    if (lastScan.findings.length > 5) lines.push('...and ' + (lastScan.findings.length - 5) + ' more in the report.');
    return lines.join('\n');
  }

  // answer: chooses a reply. Scan-related questions use the last result,
  // then keyword matching, then a help message as fallback.
  function answer(q) {
    var t = q.toLowerCase();
    if (/explain|last scan|my scan|result|report/.test(t)) return explainLast();
    for (var i = 0; i < KB.length; i++) {
      for (var j = 0; j < KB[i].k.length; j++) {
        if (t.indexOf(KB[i].k[j]) > -1) return KB[i].a;
      }
    }
    return 'I can help with scan results, XSS, phishing, CSP, SQL injection, HTTPS, secrets and CSRF. Try rephrasing with one of those terms.';
  }

  // ask: trims the question to 500 characters, shows it and the reply in the
  // chat, then clears the input box.
  function ask(q) {
    q = String(q || '').trim().slice(0, 500);
    if (!q) return;
    var chat = $('chat');
    chat.appendChild(el('div', 'msg me', q));
    chat.appendChild(el('div', 'msg bot', answer(q)));
    chat.scrollTop = chat.scrollHeight;
    $('input-ai').value = '';
  }

  // ---------- Feedback (stays local) ----------
  function sendFeedback() {
    var out = $('out-feedback');
    clear(out);
    out.appendChild(el('p', 'ok', 'Thanks for your feedback! (It is not stored or sent anywhere.)'));
  }

  // ---------- Wire up (no inline handlers, so CSP can block all inline code) ----------
  // init: attaches every click and keyboard handler here instead of using inline
  // onclick attributes, so the CSP can block all inline code.
  function init() {
    document.querySelectorAll('.tabs [role=tab]').forEach(function (b) {
      b.addEventListener('click', function () { showTab(b.dataset.tab); });
    });
    $('btn-scan').addEventListener('click', runScan);
    // Example buttons: put the sample in the box, then scan it right away.
    document.querySelectorAll('[data-ex]').forEach(function (b) {
      b.addEventListener('click', function () {
        $('input-scan').value = EXAMPLES[b.dataset.ex] || '';
        runScan();
      });
    });
    $('btn-clear-scan').addEventListener('click', function () { $('input-scan').value = ''; clear($('out-scan')); });
    $('btn-syntax').addEventListener('click', runSyntax);
    $('btn-ai').addEventListener('click', function () { ask($('input-ai').value); });
    $('input-ai').addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask($('input-ai').value); }
    });
    document.querySelectorAll('.quick').forEach(function (b) {
      b.addEventListener('click', function () { ask(b.dataset.q); });
    });
    $('btn-feedback').addEventListener('click', sendFeedback);
    $('chat').appendChild(el('div', 'msg bot', answer('hello')));
  }

  // Run init as soon as the page has finished loading.
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

// =====================================================================
// SAMPLE TESTS (quick self-check)
// What it does: runs 11 small known inputs (URLs, a phishing message,
// vulnerable code, syntax snippets) through window.SecureScan and shows
// PASS or FAIL for each one.
// How to use: click "Run sample tests" at the bottom of index.html.
// How to add a test: add one { name, run } entry to the TESTS array;
// run() must return true (pass) or false (fail).
// It only uses textContent, so the strict CSP still holds.
// =====================================================================
(function () {
  'use strict';

  var S = window.SecureScan;

  // Helper: true if the scan result contains a finding with this rule id.
  function has(res, id) { return res.findings.some(function (f) { return f.ruleId === id; }); }

  // Each test: a name and a function returning true (pass) or false (fail).
  var TESTS = [
    { name: 'Safe URL has no findings', run: function () {
      var r = S.scan('https://example.com/'); return r.findings.length === 0; } },
    { name: 'URL with "@" and an IP address is flagged (URL-003, URL-004, URL-011)', run: function () {
      var r = S.scan('http://secure-paypal.login-verify.xyz@192.168.4.7:8080/signin?password=abc123');
      return has(r, 'URL-003') && has(r, 'URL-004') && has(r, 'URL-011'); } },
    { name: 'Link shortener is flagged (URL-006)', run: function () {
      return has(S.scan('https://bit.ly/3xYz'), 'URL-006'); } },
    { name: 'javascript: URL is High risk (URL-001)', run: function () {
      var r = S.scan('javascript:alert(1)'); return has(r, 'URL-001') && r.findings[0].risk === 'High'; } },
    { name: 'Phishing message is flagged (MSG-001, MSG-002, MSG-004)', run: function () {
      var r = S.scan('URGENT: your account has been suspended. Verify your password within 24 hours.');
      return has(r, 'MSG-001') && has(r, 'MSG-002') && has(r, 'MSG-004'); } },
    { name: 'eval() is flagged as High risk (MWG-001)', run: function () {
      var r = S.scan('eval(userInput);'); return has(r, 'MWG-001') && r.findings[0].risk === 'High'; } },
    { name: 'innerHTML assignment is flagged as XSS (MWG-002)', run: function () {
      return has(S.scan('el.innerHTML = name;'), 'MWG-002'); } },
    { name: 'Hard-coded key is flagged and hidden (MWG-005)', run: function () {
      var r = S.scan('const apiKey = "sk_live_12345678";');
      return has(r, 'MWG-005') && r.findings[0].evidence === '(hidden for safety)'; } },
    { name: 'Empty input returns an error', run: function () {
      return !!S.scan('   ').error; } },
    { name: 'Syntax check: clean code has no issues', run: function () {
      return S.checkSyntax('const x = 1;').length === 0; } },
    { name: 'Syntax check: unclosed "{" is reported', run: function () {
      return S.checkSyntax('function f() {\n  return 1;\n').some(function (i) { return i.level === 'Error'; }); } }
  ];

  // Run all tests, then show one PASS/FAIL line each plus a total.
  function runTests() {
    var out = document.getElementById('out-test');
    while (out.firstChild) out.removeChild(out.firstChild);
    var passed = 0;
    TESTS.forEach(function (t) {
      var ok;
      try { ok = !!t.run(); } catch (e) { ok = false; }
      if (ok) passed++;
      var p = document.createElement('p');
      p.className = ok ? 'ok' : 'err';
      p.textContent = (ok ? 'PASS: ' : 'FAIL: ') + t.name;
      out.appendChild(p);
    });
    var total = document.createElement('p');
    total.textContent = passed + ' of ' + TESTS.length + ' tests passed.';
    out.appendChild(total);
  }

  document.getElementById('btn-test').addEventListener('click', runTests);
})();
