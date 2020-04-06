import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/* CompliantNode refers to a node that follows the rules (not malicious)*/
public class CompliantNode implements Node {

    private double p_graph;
    private double p_malicious;
    private double p_txDistribution;

    private int maxRounds;
    private int curRound;

    Set<Transaction> pending;
    Set<Transaction> consesus;
    private boolean[] followees;

    public CompliantNode(double p_graph, double p_malicious, double p_txDistribution, int numRounds) {
        this.p_graph = p_graph;
        this.p_malicious = p_malicious;
        this.p_txDistribution = p_txDistribution;
        this.maxRounds = numRounds;
        consesus = new HashSet<>();
    }

    public void setFollowees(boolean[] followees) {
        this.followees = Arrays.copyOf(followees,followees.length);
    }

    public void setPendingTransaction(Set<Transaction> pendingTransactions) {
        this.pending = pendingTransactions;
    }

    public Set<Transaction> sendToFollowers() {
        if(curRound == maxRounds - 1){
            return consesus;
        }
        curRound++;
        Set<Transaction> result = new HashSet<>(pending);
        consesus.addAll(pending);
        pending.clear();
        return result;
    }

    public void receiveFromFollowees(Set<Candidate> candidates) {
        Set<Integer> senders = candidates.stream().map(c -> c.sender).collect(Collectors.toSet());
        for (int i = 0; i < followees.length; i++) {
            if(followees[i] && !senders.contains(i)) followees[i] = false;
        }
        for(Candidate c : candidates) {
            if(!followees[c.sender]) continue;
            if(!consesus.contains(c.tx)) pending.add(c.tx);
        }
    }
}
