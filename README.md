# doh-investigation
A repository for scripts used in investigating DNS over HTTPS traffic.

gen_doh.py

This script will use the `doh-proxy` script from Facebook to generate DoH requests. Some modifications need to be made to the dohproxy package:
- `utils.py`: Add the following:
```
import sslkeylog
sslkeylog.set_keylog("/root/sslkeylog.txt")   
```
- `client_protocol.py`
```
        sslctx = utils.create_custom_ssl_context(
            #insecure=self.args.insecure,
            insecure=True,
            cafile=self.args.cafile
        )
```

doh2dns.py

This script will run `tshark` and use the provided SSLKEYLOG file to decrypt TLS packets. DoH GET requests are identified and printed out.
