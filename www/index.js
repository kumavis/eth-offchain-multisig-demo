import Worker from 'worker-loader!./worker.js';

const button = document.getElementById('keygen'),
  progress = document.getElementById('progress'),
  label = document.getElementById('label'),
  data = document.getElementById('data'),
  json = document.getElementById('json'),
  complete = document.getElementById('complete');

function show(el) {
  el.style.display = 'flex';
}

function hide(el) {
  el.style.display = 'none';
}

let actionType = 'keygen';
let actionData = {};
// Message must be Vec<u8>, do not use Uint8Array as that
// gets serialized to a JSON object.
const messages = [[79, 77, 69, 82], [38, 22, 90, 212], [34, 56, 29, 32]];
const message = messages[Math.floor(Math.random() * messages.length)];

if (window.Worker) {
  const worker = new Worker('worker.js');
  worker.onmessage = (e) => {
    if (e.data.type === 'ready') {
      show(button);
      button.addEventListener('click', (_) => {
        show(progress);
        if (actionType === 'sign_message') {
          hide(data);
          label.innerText = 'Signing message...';
        } else if (actionType === 'verify_signature') {
          hide(progress);
          hide(button);
          hide(data);
        }
        // Tell the web worker to call WASM
        worker.postMessage({type: actionType, ...actionData})
      });
    } else if (e.data.type === 'keygen_done') {
      hide(progress);
      // Key generation is completed
      show(data);
      json.innerText = JSON.stringify(e.data.keys, undefined, 2);

      // Prepare for next phase
      button.innerText = 'Sign message';
      actionType = 'sign_message';
      actionData = {message};

    } else if (e.data.type === 'sign_message_done') {
      hide(progress);

      show(data);
      data.querySelector('summary').innerText = "Signed data";
      json.innerText = JSON.stringify(e.data.signed, undefined, 2);

      button.innerText = 'Verify signature';
      actionType = 'verify_signature';

    } else if (e.data.type === 'verify_signature_done') {
      show(complete);
    }
  }
} else {
  console.log('Your browser doesn\'t support web workers.');
}
