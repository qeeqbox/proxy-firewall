# HTTPS Proxy Firewall
HTTPS Proxy Firewall for testing PI

### Run
```sh
python3 qbproxy.py --block-website example
```
```sh
python3 qbproxy.py --block-website example --block-content 8.8.8.8
```

### Install Root CA
- Download the cert from http://cert.cert
- Import it into your browser
- Set the proxy to 127.0.0.1 8080

### Or use Root CA directly
```sh
curl --proxy 127.0.0.1:8080 curl https://example.com/action_page.php -d "test=value1" --cacert root_ca.crt
```
