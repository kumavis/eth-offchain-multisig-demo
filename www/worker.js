// NOTE: must be an asynchronous import
import('emerald-city')
  .then((wasm) => {
    const signThreshold = 2;
    const numParties = 3;
    let keys;
    onmessage = (e) => {
      const {data} = e;
      if (data.type === 'keygen') {
        keys = wasm.keygen(signThreshold, numParties);
        postMessage({type: 'keygen_done', keys});
      } else if (data.type === 'verify_sign') {
        wasm.verify_sign(signThreshold, numParties, keys);
        postMessage({type: 'verify_sign_done', keys});
      }
    }
    postMessage({type: 'ready'});
  })
  .catch(e => console.error('Error importing wasm module `emerald-city`:', e));

