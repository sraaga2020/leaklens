# Demo walkthrough

1. Open LeakLens and select **Run scan**.
2. `demo_vulnerable.py` will appear with two deliberately fake, non-functional credentials.
3. Open **Review with AI** to show the false-positive check.
4. Click **Auto-remediate** on either finding. LeakLens creates a `.bak` backup, replaces the inline value with an environment-variable reference, and adds a safe placeholder to `.env.example`.
5. Run the scan again to demonstrate that the finding was removed.

Do not put real secrets in this file. It exists only for a presentation/demo.
