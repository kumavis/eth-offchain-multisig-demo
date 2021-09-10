// NOTE: must be an asynchronous import
import('../pkg/emerald_city.js')
  .then((wasm) => {
    const signThreshold = 2;
    const numParties = 3;
    const ttag = 3;

    // Store WASM response values here for now
    let keys, signed;

    onmessage = (e) => {
      const {data} = e;
      if (data.type === 'keygen') {
        keys = wasm.keygen(signThreshold, numParties);
        postMessage({type: 'keygen_done', keys});
      } else if (data.type === 'sign_message') {
        const {message} = data;
        signed = wasm.sign_message(signThreshold, ttag, keys, message);
        postMessage({type: 'sign_message_done', signed});
      } else if (data.type === 'verify_signature') {
        wasm.verify_signature(ttag, signed);
        postMessage({type: 'verify_signature_done', keys});
      }
    }
    postMessage({type: 'ready'});
  })
  .catch(e => console.error('Error importing wasm module `emerald-city`:', e));

