package validation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

public class UTXOPool {

    /**
     * The current collection of UTXOs, with each one mapped to its corresponding transaction output
     */
    private HashMap<UTXO, Transaction.Output> H;

    /** Creates a new empty validation.UTXOPool */
    public UTXOPool() {
        H = new HashMap<UTXO, Transaction.Output>();
    }

    /** Creates a new validation.UTXOPool that is a copy of {@code uPool} */
    public UTXOPool(UTXOPool uPool) {
        H = new HashMap<UTXO, Transaction.Output>(uPool.H);
    }

    /** Adds a mapping from validation.UTXO {@code utxo} to transaction output @code{txOut} to the pool */
    public void addUTXO(UTXO utxo, Transaction.Output txOut) {
        H.put(utxo, txOut);
    }

    /** Removes the validation.UTXO {@code utxo} from the pool */
    public void removeUTXO(UTXO utxo) {
        H.remove(utxo);
    }

    /**
     * @return the transaction output corresponding to validation.UTXO {@code utxo}, or null if {@code utxo} is
     *         not in the pool.
     */
    public Transaction.Output getTxOutput(UTXO ut) {
        return H.get(ut);
    }

    /** @return true if validation.UTXO {@code utxo} is in the pool and false otherwise */
    public boolean contains(UTXO utxo) {
        return H.containsKey(utxo);
    }

    /** Returns an {@code ArrayList} of all UTXOs in the pool */
    public ArrayList<UTXO> getAllUTXO() {
        Set<UTXO> setUTXO = H.keySet();
        ArrayList<UTXO> allUTXO = new ArrayList<UTXO>();
        for (UTXO ut : setUTXO) {
            allUTXO.add(ut);
        }
        return allUTXO;
    }
}
