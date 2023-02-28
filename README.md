# HTTPS Proxy Firewall
HTTPS Proxy Firewall for testing PI

### Run
```sh
python3 qbproxy.py
```

### Install Root CA
Go to http://cert.cert

### Or use Root CA directly
```sh
curl --proxy 127.0.0.1:8080 curl https://example.com/action_page.php -d "test=value1" --cacert root_ca.crt
```
