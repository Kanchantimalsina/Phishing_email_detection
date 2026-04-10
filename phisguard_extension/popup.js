const API_BASE = 'http://127.0.0.1:8000/api/detection';
const STORAGE_KEY = 'installation_id';
const ANALYZE_PAGE_URL = 'http://localhost:5173/analyze';
const PREFILL_BODY_LIMIT = 6000;
const MAIL_HOSTS = ['mail.google.com', 'outlook.office.com', 'outlook.office365.com', 'outlook.live.com'];

const scanBtn = document.getElementById('scanBtn');
const statusText = document.getElementById('statusText');
const resultCard = document.getElementById('resultCard');
const verdictEl = document.getElementById('verdict');
const riskTextEl = document.getElementById('riskText');
const gaugeFill = document.getElementById('gaugeFill');
const reasonsList = document.getElementById('reasonsList');

function makeInstallationId() {
	if (typeof crypto !== 'undefined' && crypto.randomUUID) {
		return crypto.randomUUID();
	}
	return `phg-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function getStorage(keys) {
	return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

function setStorage(payload) {
	return new Promise((resolve) => chrome.storage.local.set(payload, resolve));
}

async function getInstallationId() {
	const data = await getStorage([STORAGE_KEY]);
	let id = data[STORAGE_KEY];
	if (!id) {
		id = makeInstallationId();
		await setStorage({ [STORAGE_KEY]: id });
	}
	return id;
}

function setStatus(text, isError = false) {
	statusText.textContent = text;
	statusText.classList.toggle('error', isError);
}

function riskColor(score) {
	if (score >= 60) return '#ef4444';
	if (score >= 30) return '#f59e0b';
	return '#22c55e';
}

function renderResult(result) {
	const score = Math.max(0, Math.min(100, Number(result.risk_score || 0)));
	const verdict = (result.verdict || 'safe').toUpperCase();
	const reasons = result.reasons || (result.indicators || []).map((item) => item.description).filter(Boolean);

	resultCard.classList.remove('hidden');

	verdictEl.textContent = verdict;
	riskTextEl.textContent = `${score.toFixed(1)}%`;
	gaugeFill.style.width = `${score}%`;
	gaugeFill.style.background = riskColor(score);

	reasonsList.innerHTML = '';
	if (!reasons.length) {
		const li = document.createElement('li');
		li.textContent = 'No suspicious indicators detected.';
		reasonsList.appendChild(li);
	} else {
		reasons.slice(0, 5).forEach((reason) => {
			const li = document.createElement('li');
			li.textContent = `Flagged: ${reason}`;
			reasonsList.appendChild(li);
		});
	}
}

function getActiveTab() {
	return new Promise((resolve) => {
		chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0]));
	});
}

function sendExtractRequest(tabId) {
	return new Promise((resolve) => {
		chrome.tabs.sendMessage(tabId, { type: 'PHISHGUARD_EXTRACT_EMAIL' }, (response) => {
			if (chrome.runtime.lastError) {
				resolve({ ok: false, error: chrome.runtime.lastError.message });
				return;
			}
			resolve(response || { ok: false, error: 'No response from content script.' });
		});
	});
}

function canAutoInject(errorMessage) {
	const message = (errorMessage || '').toLowerCase();
	return message.includes('receiving end does not exist') || message.includes('could not establish connection');
}

function injectContentScript(tabId) {
	return new Promise((resolve) => {
		chrome.scripting.executeScript(
			{
				target: { tabId },
				files: ['content.js'],
			},
			() => {
				if (chrome.runtime.lastError) {
					resolve({ ok: false, error: chrome.runtime.lastError.message });
					return;
				}
				resolve({ ok: true });
			}
		);
	});
}

function isSupportedMailUrl(url) {
	if (!url) return false;
	return MAIL_HOSTS.some((host) => url.includes(host));
}

async function sendExtractWithRecovery(tabId) {
	let extracted = await sendExtractRequest(tabId);

	if (extracted.ok || !canAutoInject(extracted.error)) {
		return extracted;
	}

	const injected = await injectContentScript(tabId);
	if (!injected.ok) {
		return {
			ok: false,
			error: injected.error || 'Could not initialize page scanner. Refresh the mail tab and try again.',
		};
	}

	return sendExtractRequest(tabId);
}

function buildPrefillUrl(extracted, source) {
	const compactPayload = {
		sender: extracted.sender || '',
		subject: extracted.subject || '',
		body: (extracted.body || '').slice(0, PREFILL_BODY_LIMIT),
		source,
	};

	const json = JSON.stringify(compactPayload);
	const encoded = btoa(unescape(encodeURIComponent(json)));
	return `${ANALYZE_PAGE_URL}?prefill=${encodeURIComponent(encoded)}`;
}

function openAnalyzePageWithPrefill(extracted, tabUrl) {
	const source = tabUrl.includes('mail.google.com') ? 'gmail-extension' : 'outlook-extension';
	const url = buildPrefillUrl(extracted, source);

	return new Promise((resolve) => {
		chrome.tabs.create({ url }, () => resolve());
	});
}

async function extractFromActiveMailTab() {
	const tab = await getActiveTab();
	if (!tab?.id || !tab.url) {
		throw new Error('No active tab found.');
	}

	if (!isSupportedMailUrl(tab.url)) {
		throw new Error('Open a Gmail or Outlook email first.');
	}

	const extracted = await sendExtractWithRecovery(tab.id);
	if (!extracted.ok) {
		throw new Error(extracted.error || 'Could not extract email content.');
	}

	if (!extracted.body && !extracted.subject) {
		throw new Error('No readable email content found. Open a specific email and try again.');
	}

	return { extracted, tab };
}

async function sendToAnalyzePage() {
	setStatus('Extracting email and opening Analyze page...');

	try {
		const { extracted, tab } = await extractFromActiveMailTab();
		await openAnalyzePageWithPrefill(extracted, tab.url);
		setStatus('Analyze page opened with pre-filled email details.');
	} catch (error) {
		console.error('Prefill error:', error);
		setStatus(error.message || 'Could not open Analyze page.', true);
	}
}

async function analyzeCurrentEmail() {
	setStatus('Extracting email content...');
	scanBtn.disabled = true;

	try {
		const installationId = await getInstallationId();

		const { extracted, tab } = await extractFromActiveMailTab();

		setStatus('Sending for phishing analysis...');

		const response = await fetch(`${API_BASE}/analyze/`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				installation_id: installationId,
				sender: extracted.sender || '',
				subject: extracted.subject || '',
				body: extracted.body || '',
				source: tab.url.includes('mail.google.com') ? 'gmail-extension' : 'outlook-extension',
			}),
		});

		const data = await response.json();
		if (!response.ok) {
			console.error('API error response:', { status: response.status, data });
			throw new Error(data.error || `API returned status ${response.status}`);
		}

		renderResult(data);
		setStatus('Scan complete.');
	} catch (error) {
		console.error('Analysis error:', error);
		setStatus(error.message || 'Scan failed.', true);
	} finally {
		scanBtn.disabled = false;
	}
}

scanBtn.addEventListener('click', analyzeCurrentEmail);

// Auto-open Analyze page with extracted content when popup is opened on a mail tab.
sendToAnalyzePage();
