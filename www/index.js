import Worker from 'worker-loader!./worker.js';

const button = document.getElementById('keygen');
const progress = document.getElementById('progress');
const label = document.getElementById('progress-label');
const keyData = document.getElementById('keydata');
const keyJson = document.getElementById('keyjson');
const complete = document.getElementById('complete');

function show(el) {
  el.style.display = 'flex';
}

function hide(el) {
  el.style.display = 'none';
}

let actionType = 'keygen';

if (window.Worker) {
  const worker = new Worker('worker.js');
  worker.onmessage = (e) => {
    const {data} = e;
    if (data.type === 'ready') {
      show(button);
      button.addEventListener('click', (_) => {
        if (actionType === 'verify_sign') {
          hide(keyData);
          label.innerText = 'Verify key signing...';
        }
        show(progress);
        // Tell the web worker to call WASM
        worker.postMessage({type: actionType})
      });
    } else if (data.type === 'keygen_done') {
      hide(progress);
      // Key generation is completed
      show(keyData);
      keyJson.innerText = JSON.stringify(data.keys, undefined, 2);

      // Prepare for next phase
      button.innerText = 'Verify sign';
      actionType = 'verify_sign'

    } else if (data.type === 'verify_sign_done') {
      hide(progress);
      hide(button);
      hide(keyData);
      show(complete);
    }
  }
} else {
  console.log('Your browser doesn\'t support web workers.');
}
