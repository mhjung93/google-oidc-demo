import { panel, text, heading } from '@metamask/snaps-sdk';
import { Buffer } from 'buffer';

/**
 * Handle incoming JSON-RPC requests, sent through `wallet_invokeSnap`.
 *
 * @param {object} args - The request handler args as object.
 * @param {string} args.origin - The origin of the request, e.g., the website that
 * invoked the snap.
 * @param {object} args.request - A validated JSON-RPC request object.
 * @returns {unknown} A result depends on the request method.
 * @throws If the request method is not found.
 */
export const onRpcRequest = async ({ origin, request }) => {
  switch (request.method) {
    case 'hello':
      return snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            text(`Hello, **${origin}**!`),
            text('This is a demo snap for user-consent traceability.'),
          ]),
        },
      });
    case 'sendZkProof': {
      const { proof, to } = request.params;
      const ciphertext = 'ciphertext';

      const dataPayload = JSON.stringify(proof) + ciphertext;
      const data = `0x${Buffer.from(dataPayload).toString('hex')}`;

      const confirmed = await snap.request({
        method: 'snap_dialog',
        params: {
          type: 'confirmation',
          content: panel([
            heading('Send ZK Proof Transaction'),
            text(`You are about to send a transaction to **${to}**`),
            text(
              'The transaction data will contain a ZK proof and a ciphertext.',
            ),
            text(`Data: ${data.slice(0, 50)}...`),
          ]),
        },
      });

      if (confirmed) {
        //const from = (await ethereum.request({ method: 'eth_requestAccounts' }))[0];
        //const txParams = {
        //  to,
        //  from,
        //  data,
        //};

        //return await ethereum.request({
        //  method: 'eth_sendTransaction',
        //  params: [txParams],
        //});
        // ✅ Snap은 tx를 "보내지 말고", tx 파라미터를 "리턴"만 한다.
        return {
          ok: true,
          tx: {
            to,
            data,
          },
        };

      }
      return null; // User rejected
    }
    default:
      throw new Error('Method not found.');
  }
};
