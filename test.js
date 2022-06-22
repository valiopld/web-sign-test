const bitcoin = require('bitcoinjs-lib');
const { ECPairFactory } = require('ecpair');
const tinysecp = require('tiny-secp256k1');
const ECPair = ECPairFactory(tinysecp);

const LTCTEST = {
    messagePrefix: '\x19Litecoin Testnet Signed Message:\n',
    bech32: 'tltc',
    bip32: {
      public: 0x0436f6e1,
      private: 0x0436ef7d,
    },
    pubKeyHash: 0x6f,
    scriptHash: 0x3a,
    wif: 0xef,
};

const validator = (pubkey, msghash, signature) => ECPair.fromPublicKey(pubkey).verify(msghash, signature);
const psbt = new bitcoin.Psbt({ network: LTCTEST });

// generating keyPair from wif (privatekey);
const wif = 'cSqHPnwCvgUFLNzfHbyJb9egDc2PQzUzdHMwC84av5RzhuiFzbeS';
const keyPair = ECPair.fromWIF(wif, LTCTEST);
const scriptPubKey = '0014c7455f96abc49278ee0c6fb666ab2ea28453d467'; // script pubkey Of the address;
const redeemScript = Buffer.from(scriptPubKey, 'hex');


// VARIANT 1: If trying to sign existin transaction (with provided hex)
const inputs = [
    {
        hex: 'eaf4e894659323ce7e3e209ca89ceab5cc423c636605ac9bf00aef64d844df50',
        amount: 1250040800,
    }
];
const hex = '0200000001eaf4e894659323ce7e3e209ca89ceab5cc423c636605ac9bf00aef64d844df500000000000ffffffff0160db794a0000000017a914623edc8037680e08664586bc1f2203693ea7759d8700000000';
const tx = bitcoin.Transaction.fromHex(hex);

const convertedIns = tx.ins.map(_in => {
    const value = inputs.find(r => r.hex === _in.hash.toString('hex')).amount;
    _in.redeemScript = redeemScript;
    _in.witnessUtxo = { script: redeemScript, value };
    return _in;
});

psbt.addInputs(convertedIns);
psbt.addOutputs(tx.outs);
//End VARIANT 1


// VARIANT 2 - if Building the transaction from scratch just use:
// psbt.addInput({
//     hash: Buffer.from("eaf4e894659323ce7e3e209ca89ceab5cc423c636605ac9bf00aef64d844df50", 'hex'), // the txId for signing
//     index: 0, // the voutOftheTx,
//     redeemScript: redeemScript, // redeemScript of the address
//     witnessUtxo: { script: redeemScript, value: 1250040800 },
// });
// psbt.addOutput({
//     address: 'QVZTdnCfeYuP2pjhPGUDsZxt4Z6oqYACxQ', // address to send
//     value: 1245040800, // amount to send
// });
// End VARIANT 2


psbt.signAllInputs(keyPair)
const isValid = psbt.validateSignaturesOfAllInputs(validator)
if (isValid) {
    psbt.finalizeAllInputs();
    const signedHex = psbt.extractTransaction().toHex();
    console.log({signedHex});
}