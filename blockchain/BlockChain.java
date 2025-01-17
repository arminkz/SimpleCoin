// Block Chain should maintain only limited block nodes to satisfy the functions
// You should not have all the blocks added to the block chain in memory 
// as it would cause a memory overflow.

import java.util.ArrayList;
import java.util.HashMap;

public class BlockChain {
    public static final int CUT_OFF_AGE = 10;

    class BlockChainNode {
        private Block block;
        private BlockChainNode parent;
        private ArrayList<BlockChainNode> children;
        private int height;
        private UTXOPool utxoPool;

        public BlockChainNode(Block b, BlockChainNode parent, UTXOPool uPool) {
            this.block = b;
            this.parent = parent;
            this.children = new ArrayList<>();
            this.utxoPool = uPool;
            if(parent != null) {
                parent.children.add(this);
                height = parent.height + 1;
            }else {
                height = 1;
            }
        }

        public Block getBlock() {
            return block;
        }

        public UTXOPool getUTXOPoolCopy() {
            return new UTXOPool(utxoPool);
        }
    }

    // Hash Pointer implementation
    private HashMap<ByteArrayWrapper, BlockChainNode> blockChain;

    private BlockChainNode maxHeightNode;
    private TransactionPool txPool;


    private void addCoinbaseToUTXOPool(Block block, UTXOPool utxoPool) {
        Transaction coinbase = block.getCoinbase();
        for (int i = 0; i < coinbase.numOutputs(); i++) {
            Transaction.Output out = coinbase.getOutput(i);
            UTXO utxo = new UTXO(coinbase.getHash(), i);
            utxoPool.addUTXO(utxo, out);
        }
    }

    /**
     * create an empty block chain with just a genesis block. Assume {@code genesisBlock} is a valid
     * block
     */
    public BlockChain(Block genesisBlock) {
        // init txPool
        txPool = new TransactionPool();
        // init Blockchain
        blockChain = new HashMap<>();
        // initial UTXOs are the Coinbase of the Genesis Block
        UTXOPool utxoPool = new UTXOPool();
        addCoinbaseToUTXOPool(genesisBlock, utxoPool);
        // add genesis Block to Blockchain
        BlockChainNode genesisNode = new BlockChainNode(genesisBlock,null, utxoPool);
        blockChain.put(new ByteArrayWrapper(genesisBlock.getHash()),genesisNode);
        maxHeightNode = genesisNode;
    }

    /** Get the maximum height block */
    public Block getMaxHeightBlock() {
        return maxHeightNode.getBlock();
    }

    /** Get the UTXOPool for mining a new block on top of max height block */
    public UTXOPool getMaxHeightUTXOPool() {
        return maxHeightNode.getUTXOPoolCopy();
    }

    /** Get the transaction pool to mine a new block */
    public TransactionPool getTransactionPool() {
        return txPool;
    }

    /**
     * Add {@code block} to the block chain if it is valid. For validity, all transactions should be
     * valid and block should be at {@code height > (maxHeight - CUT_OFF_AGE)}.
     * 
     * <p>
     * For example, you can try creating a new block over the genesis block (block height 2) if the
     * block chain height is {@code <=
     * CUT_OFF_AGE + 1}. As soon as {@code height > CUT_OFF_AGE + 1}, you cannot create a new block
     * at height 2.
     * 
     * @return true if block is successfully added
     */
    public boolean addBlock(Block block) {
        byte[] prevBlockHash = block.getPrevBlockHash();
        if (prevBlockHash == null)
            return false;
        BlockChainNode parentBlockNode = blockChain.get(new ByteArrayWrapper(prevBlockHash));
        if (parentBlockNode == null) {
            return false;
        }

        TxHandler handler = new TxHandler(parentBlockNode.getUTXOPoolCopy());
        Transaction[] txs = block.getTransactions().toArray(new Transaction[0]);
        Transaction[] validTxs = handler.handleTxs(txs);
        // all transactions must be valid
        if (validTxs.length != txs.length) {
            return false;
        }
        // height mustt be valid
        int proposedHeight = parentBlockNode.height + 1;
        if (proposedHeight <= maxHeightNode.height - CUT_OFF_AGE) {
            return false;
        }
        // update UTXO
        UTXOPool utxoPool = handler.getUTXOPool();
        addCoinbaseToUTXOPool(block, utxoPool);
        BlockChainNode node = new BlockChainNode(block, parentBlockNode, utxoPool);
        // add block to blockchain
        blockChain.put(new ByteArrayWrapper(block.getHash()), node);
        // update maxHeight node
        if (proposedHeight > maxHeightNode.height) {
            maxHeightNode = node;
        }
        return true;
    }

    /** Add a transaction to the transaction pool */
    public void addTransaction(Transaction tx) {
        txPool.addTransaction(tx);
    }
}