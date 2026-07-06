window.addEventListener('load', () => {
  const connectButton = document.getElementById('connectButton');
  const helloButton = document.getElementById('helloButton');
  const spendButton = document.getElementById('spendButton');
  const sendProofButton = document.getElementById('sendProofButton');

  let accounts = [];

  // The snap ID is determined by the snap's package name and the server port.
  const snapId = 'local:http://localhost:8081';

  // --- ADD: Ensure the current origin (http://localhost:3000) has permission for the snap ---
  async function ensureSnapPermission() {
    if (!window.ethereum) throw new Error('MetaMask not found');

    // Request install/enable permission for this origin
    await window.ethereum.request({
      method: 'wallet_requestSnaps',
      params: { [snapId]: {} },
    });
  }

  // --- ADD: Safe invoke wrapper (always ensure permission before invoke) ---
  async function invokeSnap(request) {
    await ensureSnapPermission();
    return await window.ethereum.request({
      method: 'wallet_invokeSnap',
      params: { snapId, request },
    });
  }
  

  connectButton.addEventListener('click', async () => {
    try {
      // Check if MetaMask is installed
      if (!window.ethereum) {
        alert('Please install MetaMask first.');
        return;
      }

      const hardhatChainId = '0x7A69'; // 31337 in hex

      try {
        // Try to switch to the Hardhat network
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: hardhatChainId }],
        });
      } catch (switchError) {
        // This error code indicates that the chain has not been added to MetaMask.
        if (switchError.code === 4902) {
          try {
            // Try to add the Hardhat network
            await window.ethereum.request({
              method: 'wallet_addEthereumChain',
              params: [
                {
                  chainId: hardhatChainId,
                  chainName: 'Hardhat',
                  rpcUrls: ['http://127.0.0.1:8545'],
                  nativeCurrency: {
                    name: 'Ethereum',
                    symbol: 'ETH',
                    decimals: 18,
                  },
                },
              ],
            });
          } catch (addError) {
            console.error('Failed to add the Hardhat network:', addError);
            alert('Failed to add the Hardhat network. Please do it manually.');
            return;
          }
        } else {
          console.error('Failed to switch to the Hardhat network:', switchError);
          alert('Failed to switch to the Hardhat network.');
          return;
        }
      }

      // ✅ 이 origin(http://localhost:3000)에서 스냅을 "설치/권한부여" 받는 단계
      await ethereum.request({
        method: 'wallet_requestSnaps',
        params: {
          [snapId]: {},
        },
      });


      // Request accounts
      accounts = await ethereum.request({
        method: 'eth_requestAccounts',
      });

      


      // --- ADD: request snap permission for this origin (localhost:3000) ---
      await ensureSnapPermission();

      //connectButton.textContent = 'Connected';
      connectButton.textContent = 'Connected (re-click to reinstall snap)';
      //connectButton.disabled = true;
      helloButton.disabled = false;
      spendButton.disabled = false;
      sendProofButton.disabled = false;
    } catch (error) {
      console.error('Connection error:', error);
      connectButton.textContent = 'Connection Failed';
    }
  });

  helloButton.addEventListener('click', async () => {
    try {
      const response = await invokeSnap({ method: 'hello' });
      console.log('Response from snap:', response);
    } catch (err) {
      console.error('Error invoking snap:', err);
    }
  });


  sendProofButton.addEventListener('click', async () => {
    try {
      const proofResponse = await fetch('/build/proof.json');
      if (!proofResponse.ok) {
        throw new Error('Could not fetch proof.json. Make sure the ZKP has been generated.');
      }
      const proof = await proofResponse.json();
      
      const toAddress = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'; // An example address (vitalik.eth)

      const response = await invokeSnap({
        method: 'sendZkProof',
        params: { proof, to: toAddress },
      });

      console.log('Transaction response from snap:', response);
      if (response) {
        alert(`Transaction sent! Hash: ${response}`);
      } else {
        alert('Transaction was rejected.');
      }
    } catch (err) {
      console.error('Error sending proof to snap:', err);
      alert(`Error: ${err.message}`);
    }
  });

  spendButton.addEventListener('click', async () => {
    if (accounts.length === 0) {
      alert('Please connect your wallet first.');
      return;
    }

    const transactionParameters = {
      chainId: '0x7A69', // Hardhat network chain ID (31337)
      from: accounts[0],
      to: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', // An example address (vitalik.eth)
      value: '0x2540BE400', // 10 Gwei in wei, converted to hex
    };

    const valueInGwei = parseInt(transactionParameters.value, 16) / 1e9;
    const toAddress = transactionParameters.to;

    // Show a confirmation dialog first
    if (window.confirm(`Do you want to send ${valueInGwei} Gwei to ${toAddress}?`)) {

                  // --- New flow with updated delays ---

                  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

            

                  try {

                    // 1. Initial delay

                    await sleep(860);

            

                    // 2. Generate Pseudonym (with delay)

                    await sleep(650);

                    const keyPair = {

                      publicKey: '0x04...publicKey...',

                      privateKey: '0x...privateKey...',

                    };

                    alert(`generate pseudonym: ${JSON.stringify(keyPair)}`);

            

                    // 3. Generate ZKP and Transaction (with delay)

                    await sleep(5254); // 0.544s + 4.71s = 5.254s

                    const placeholderZKP = {

                      pi_a: ['0x...', '0x...'],

                      pi_b: [['0x...', '0x...'], ['0x...', '0x...']],

                      pi_c: ['0x...', '0x...'],

                      protocol: 'groth16',

                      curve: 'bn128'

                    };

                    const toHexString = (str) => {

                      let hex = '';

                      for (let i = 0; i < str.length; i++) {

                        const charCode = str.charCodeAt(i).toString(16);

                        hex += charCode.padStart(2, '0');

                      }

                      return `0x${hex}`;

                    };

                                    const zkpData = toHexString(JSON.stringify(placeholderZKP));

                                    transactionParameters.data = zkpData;

                                    const txContents = JSON.stringify(transactionParameters, null, 2);

                                    alert(`generate transaction: ${txContents}`);

            

                    // 4. Send the actual transaction

                    const txHash = await ethereum.request({

                      method: 'eth_sendTransaction',

                      params: [transactionParameters],

                    });

                    console.log('Transaction successful with hash:', txHash);

            

                  } catch (error) {

                    console.error('Flow failed:', error);

                    alert(`Error: ${error.message}`);

                  }

                } else {

                  console.log('Transaction cancelled by user.');

                }
  });
});
