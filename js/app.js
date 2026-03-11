// core DOM references
const payloadInput = document.getElementById('payload-input');
const hashToggle = document.getElementById('hash-toggle');
const logicLabel = document.getElementById('logic-label');
const computeBtn = document.getElementById('compute-hash-btn');
const packetPreview = document.getElementById('packet-preview');
const transmitBtn = document.getElementById('transmit-btn');
const interceptToggle = document.getElementById('intercept-toggle');

const receivedInput = document.getElementById('received-input');
const validateBtn = document.getElementById('validate-btn');

const resultSection = document.getElementById('result-section');
const statusAlert = document.getElementById('status-alert');
const statusTitle = document.getElementById('status-title');
const statusDesc = document.getElementById('status-desc');
const statusIcon = document.getElementById('status-icon');
const tableReceivedHash = document.getElementById('table-received-hash');
const tableComputedHash = document.getElementById('table-computed-hash');

// state
let currentPayload = '';
let currentSentHash = '';
let currentMethod = 'MD5';
let interceptEnabled = false;

hashToggle.addEventListener('change', (e) => {
  currentMethod = e.target.checked ? 'SHA-1' : 'MD5';
  logicLabel.textContent = currentMethod;
});

interceptToggle.addEventListener('change', (e) => {
  interceptEnabled = e.target.checked;
});

computeBtn.addEventListener('click', generateDigest);
transmitBtn.addEventListener('click', sendPacket);
validateBtn.addEventListener('click', verifyIntegrity);

/* helpers */
function computeHash(message, method) {
  if (method === 'MD5') {
    return CryptoJS.MD5(message).toString();
  }
  // SHA-1 by default
  return CryptoJS.SHA1(message).toString();
}

function mutate(str) {
  if (str.length === 0) return 'X';
  const idx = Math.floor(Math.random() * str.length);
  const char = String.fromCharCode(97 + Math.floor(Math.random() * 26));
  return str.slice(0, idx) + char + str.slice(idx + 1);
}

/* main business logic */
function generateDigest() {
  currentPayload = payloadInput.value || 'VOID_DATA';
  currentSentHash = computeHash(currentPayload, currentMethod);
  packetPreview.innerHTML =
    `<span class="text-mutedPurple">MSG:</span> ${currentPayload.slice(0, 8)}... <br/>` +
    `<span class="text-primaryPurple font-bold">${currentMethod}:</span> ` +
    `<span class="text-primaryPurple">${currentSentHash.slice(0, 16)}...</span>`;
  packetPreview.classList.add('border-primaryPurple/30');
}

function sendPacket() {
  if (!currentSentHash) {
    alert('Please generate a hash first.');
    return;
  }

  let message = currentPayload;
  let digest = currentSentHash;

  if (interceptEnabled) {
    if (Math.random() < 0.5) {
      message = mutate(message);
    } else {
      digest = mutate(digest);
    }
  }

  const packet = `${message} || ${digest}`;
  receivedInput.value = packet;

  // simple visual feedback for transmission
  transmitBtn.classList.add('opacity-80');
  setTimeout(() => transmitBtn.classList.remove('opacity-80'), 200);
}

function verifyIntegrity() {
  const raw = receivedInput.value;
  const separatorIndex = raw.lastIndexOf('||');
  if (separatorIndex === -1) {
    alert('Invalid packet format. Expected "message || digest"');
    return;
  }

  const receivedMessage = raw.slice(0, separatorIndex).trim();
  const receivedDigest = raw.slice(separatorIndex + 2).trim();
  const recomputed = computeHash(receivedMessage, currentMethod);

  resultSection.classList.remove('hidden');
  tableReceivedHash.textContent = receivedDigest;
  tableComputedHash.textContent = recomputed;

  const isDataSameAsSent = receivedMessage === currentPayload;
  const isDigestSameAsSent = receivedDigest === currentSentHash;
  const isHashMatching = recomputed === receivedDigest;

  if (isHashMatching && isDataSameAsSent) {
    setStatus(
      'Integrity Verified',
      'The received packet matches the outbound signature perfectly.',
      'green'
    );
  } else if (!isDataSameAsSent && isDigestSameAsSent) {
    setStatus(
      'Integrity Compromised: Message Modified',
      'The payload content has been altered while the signature remains original.',
      'red'
    );
  } else if (isDataSameAsSent && !isHashMatching) {
    setStatus(
      'Integrity Compromised: Digest Modified',
      'The message text is intact, but the digital signature has been tampered with.',
      'orange'
    );
  } else {
    setStatus(
      'Integrity Compromised',
      'Full packet corruption detected. Neither data nor digest are valid.',
      'red'
    );
  }

  resultSection.scrollIntoView({ behavior: 'smooth' });
}

function setStatus(title, text, color) {
  const palette = {
    green: { bg: 'bg-green-50', border: 'border-green-200', text: 'text-green-700' },
    red: { bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-700' },
    orange: { bg: 'bg-orange-50', border: 'border-orange-200', text: 'text-orange-700' },
  };
  const c = palette[color] || palette.red;
  statusAlert.className =
    `p-4 rounded-md border flex items-center space-x-3 ${c.bg} ${c.border} ${c.text}`;
  statusTitle.textContent = title;
  statusDesc.textContent = text;
  if (color === 'green') {
    statusIcon.innerHTML =
      '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewbox="0 0 24 24">' +
      '<path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" ' +
      'stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path>' +
      '</svg>';
  } else if (color === 'orange') {
    statusIcon.innerHTML =
      '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewbox="0 0 24 24">' +
      '<path d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" ' +
      'stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path>' +
      '</svg>';
  } else {
    statusIcon.innerHTML =
      '<svg class="w-6 h-6" fill="none" stroke="currentColor" viewbox="0 0 24 24">' +
      '<path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-' +
      '.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" ' +
      'stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path>' +
      '</svg>';
  }
}
