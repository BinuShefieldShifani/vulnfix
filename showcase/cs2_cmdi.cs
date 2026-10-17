using System.Diagnostics;

public class Runner {
    public void RunPing(string host) {
        // VULNERABLE (line 5): command injection via shell
        Process.Start("cmd.exe", "/c ping " + host);
    }
}
