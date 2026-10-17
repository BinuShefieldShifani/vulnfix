public class Pinger {
    public boolean validHost(String h) {
        return h != null && !h.isEmpty();
    }
    public void ping(String host) throws Exception {
        // VULNERABLE (line 6): command injection via sh -c
        Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
    }
}
