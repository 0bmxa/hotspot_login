# Hotspot login

A WiFi hotspot login script.


## How can I use this

1. Clone it
2. Symlink `main.py` to somewhere on your path
    ```ln -s "$(pwd)/main.py" /usr/local/bin/hotspot_login```


## Supported networks

Currently the list is short:
- Mein Hotspot
    - A local Berlin coffee shop ("Books and Bagels") with some additional restrictions
- DeutscheBahn ICE Portal


## Features
- Respects if you use your own DNS (like I do)
- Translates domain names to IPs (for own DNS)


## Known issues
- Does not support IPv6 :sob:
- Has certificate issues with TLS, as domain names are replaced by IPs
- more

Please [report issues](https://github.com/0bmxa/hotspot_login/issues/new), if you find any!
