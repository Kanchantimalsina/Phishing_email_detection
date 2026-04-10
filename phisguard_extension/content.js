function pickFirstText(selectors) {
  for (const selector of selectors) {
    const node = document.querySelector(selector);
    if (node && node.textContent && node.textContent.trim()) {
      return node.textContent.trim();
    }
  }
  return '';
}

function collectBodyText(selectors) {
  for (const selector of selectors) {
    const nodes = Array.from(document.querySelectorAll(selector));
    if (!nodes.length) {
      continue;
    }

    const merged = nodes
      .map((node) => (node.textContent || '').trim())
      .filter(Boolean)
      .join('\n');

    if (merged) {
      return merged;
    }
  }
  return '';
}

function extractFromGmail() {
  const sender = pickFirstText([
    'h3.iw span[email]',
    'span.gD[email]',
    'span[email][name]',
  ]);

  const subject = pickFirstText([
    'h2.hP',
    'h2[data-legacy-thread-id]',
    '[data-thread-perm-id] h2',
  ]);

  const body = collectBodyText([
    'div.a3s.aiL',
    'div.a3s',
  ]);

  return { sender, subject, body };
}

function extractFromOutlook() {
  const sender = pickFirstText([
    '[aria-label="From"] span',
    '[data-app-section="MailReadCompose"] [title*="@"]',
    '[title*="@"]',
  ]);

  const subject = pickFirstText([
    '[role="heading"]',
    'div[aria-label="Message header"] span',
  ]);

  const body = collectBodyText([
    'div[role="document"]',
    'div[data-app-section="MailReadCompose"] div[dir="ltr"]',
  ]);

  return { sender, subject, body };
}

function extractEmailData() {
  if (location.hostname.includes('mail.google.com')) {
    return extractFromGmail();
  }
  if (location.hostname.includes('outlook.office.com')) {
    return extractFromOutlook();
  }
  return { sender: '', subject: '', body: '' };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== 'PHISHGUARD_EXTRACT_EMAIL') {
    return;
  }

  const payload = extractEmailData();
  sendResponse({
    ok: Boolean(payload.body || payload.subject),
    ...payload,
    pageUrl: location.href,
  });
});
