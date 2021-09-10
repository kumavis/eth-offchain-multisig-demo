import Worker from 'worker-loader!./worker.js';

const genKeyButton = document.getElementById('keygen'),
  verifySignatureButton = document.getElementById('verify'),
  thresholdInput = document.getElementById('threshold'),
  partiesInput = document.getElementById('parties'),
  partiesList = document.getElementById('parties-list'),
  payload = document.getElementById('payload'),
  progress = document.getElementById('progress'),
  label = document.getElementById('label'),
  data = document.getElementById('data'),
  json = document.getElementById('json'),
  params = document.getElementById('params'),
  intro = document.getElementById('intro');

// Message must be Vec<u8>, do not use Uint8Array as that
// gets serialized to a JSON object.
const message = randomMessage();

let threshold = 1;
let parties = 3;
let signingIndices = [];

payload.innerText = hex(message);
thresholdInput.value = threshold;
partiesInput.value = parties;

const show = (el) => el.style.display = 'flex';
const hide = (el) => el.style.display = 'none';

function randomMessage() {
  return (Array.apply(null, Array(32))).map(() => {
    return Math.floor(Math.random() * 256);
  });
}

thresholdInput.addEventListener('change', (e) => {
  threshold = Math.min(parseInt(e.target.value), parties - 1);
});

partiesInput.addEventListener('change', (e) => {
  parties = parseInt(e.target.value);
  thresholdInput.setAttribute('max', parties - 1);
  if (threshold >= parties)  {
    threshold = parties - 1;
    thresholdInput.value = threshold;
  }
});

function hex(bytes) {
  const chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];
  return bytes.reduce((acc, u8) => {
    acc += chars[Math.floor(u8 / 16)] + chars[u8 % 16];
    return acc
  }, '');
}

if (window.Worker) {
  const worker = new Worker('worker.js');

  function showPartyKeys(multiKey) {
    show(partiesList);
    const keys = multiKey[0];
    const sharedKeys = multiKey[1];
    const ge = multiKey[2];
    const partyKeys = [];

    const tpl = document.getElementById('party-item');

    for (let i = 0; i < parties;i++) {
      const template = tpl.content.cloneNode(true);
      const heading = template.querySelector('h3');
      const button = template.querySelector('button');
      heading.innerText = `Party ${i + 1}`;

      const partyKeyData = {
        index: i,
        key: multiKey[0][i],
        sharedKey: multiKey[1][i],
        vssScheme: multiKey[4]
      };

      const pre = template.querySelector('details > pre');
      pre.innerText = JSON.stringify(partyKeyData, undefined, 2);

      button.addEventListener('click', (e) => {
        e.currentTarget.setAttribute('disabled', '1');
        signingIndices.push(i);
        if (signingIndices.length === threshold + 1) {
          const signData = { threshold, parties, message, signingIndices, signKeys: multiKey };
          worker.postMessage({type: 'sign_message', ...signData})
          hide(partiesList);
          label.innerText = "Signing message...";
          show(progress);
        }
      });
      partiesList.appendChild(template);
    }
  }

  worker.onmessage = (e) => {
    if (e.data.type === 'ready') {
      show(genKeyButton);
      genKeyButton.addEventListener('click', (_) => {
        show(progress);
        thresholdInput.setAttribute('disabled', '1');
        partiesInput.setAttribute('disabled', '1');
        worker.postMessage({type: 'keygen', threshold, parties})
      });
      verifySignatureButton.addEventListener('click', (_) => {
          hide(progress);
          hide(verifySignatureButton);
          hide(data);
          worker.postMessage({type: 'verify_signature', threshold, parties})
      });

    } else if (e.data.type === 'keygen_done') {
      hide(progress);
      hide(genKeyButton);
      showPartyKeys(e.data.keys);
    } else if (e.data.type === 'sign_message_done') {
      hide(progress);
      show(verifySignatureButton);
      show(data);
      data.querySelector('summary').innerText = "Signed data";
      json.innerText = JSON.stringify(e.data.signed, undefined, 2);
    } else if (e.data.type === 'verify_signature_done') {
      hide(params);
      intro.innerText = "Signing verification completed!";
    }
  }
} else {
  console.log('Your browser doesn\'t support web workers.');
}
