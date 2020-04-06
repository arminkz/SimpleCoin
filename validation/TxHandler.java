package validation;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class TxHandler {

    private UTXOPool curPool;
    /**
     * Creates a public ledger whose current validation.UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the validation.UTXOPool(validation.UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        // IMPLEMENT THIS
        curPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current validation.UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no validation.UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        // IMPLEMENT THIS
        ArrayList<Transaction.Input> inputs = tx.getInputs();
        ArrayList<Transaction.Output> outputs = tx.getOutputs();
        HashSet<UTXO> spents = new HashSet<>();

        double totalInValue = 0;
        double totalOutValue = 0;

        for (int i = 0; i < inputs.size(); i++) {
            Transaction.Input in = inputs.get(i);
            UTXO u = new UTXO(in.prevTxHash,in.outputIndex);
            if(!curPool.contains(u)){
                // not in current pool
                return false;
            }
            PublicKey pb = curPool.getTxOutput(u).address;
            if(!Crypto.verifySignature(pb,tx.getRawDataToSign(i),in.signature)) {
                // invalid signature
                return false;
            }
            if(spents.contains(u)){
                // double spending
                return false;
            }
            spents.add(u);

            totalInValue += curPool.getTxOutput(u).value;
        }

        for (int i = 0; i < outputs.size(); i++) {
            Transaction.Output out = outputs.get(i);

            if(out.value < 0) return false; // negative output
            totalOutValue += out.value;
        }

        if (totalOutValue > totalInValue) return false;

        return true;
    }

    private void updatePool(Transaction tx) {

        ArrayList<Transaction.Input> inputs = tx.getInputs();
        ArrayList<Transaction.Output> outputs = tx.getOutputs();

        // inputs are spent so remove them from pool
        for (int i = 0; i < inputs.size(); i++) {
            UTXO u = new UTXO(inputs.get(i).prevTxHash, inputs.get(i).outputIndex);
            curPool.removeUTXO(u);
        }

        // add new outputs to pool
        for (int i = 0; i < outputs.size(); i++) {
            UTXO u = new UTXO(tx.getHash(), i);
            curPool.addUTXO(u,outputs.get(i));
        }

    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current validation.UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        // IMPLEMENT THIS
        ArrayList<Transaction> result = new ArrayList<>();

        HashSet<Transaction> txs = new HashSet<>(Arrays.asList(possibleTxs));
        boolean isUpdated = true;
        while (txs.size() != 0 && isUpdated) {
            isUpdated = false;
            HashSet<Transaction> valids = new HashSet<>();
            for(Transaction tx : txs) {
                if (isValidTx(tx)) {
                    valids.add(tx);
                    updatePool(tx);
                }
            }

            if(valids.size() > 0) {
                isUpdated = true;
                result.addAll(valids);
                txs.removeAll(valids);
            }
        }

        Transaction[] resultArray = new Transaction[result.size()];
        result.toArray(resultArray);
        return resultArray;
    }

}
