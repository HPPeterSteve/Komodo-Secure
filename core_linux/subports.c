/*
[Target Process]
        |
        v
[Control Layer]
 (firewall + policy)
        |
   (blocks everything)
        |
   (exception: redirects)
        v
[Proxy / Gateway Sandbox]
        |
   (inspection / log)
        |
        v
[Internet]  OR  [Fake Services / Honeypot]
*/