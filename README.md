# PyBurp2
PyBurp2 is a python interface to the new BurpSuite 2.0 REST API. Currently developed for version 0.1.

## Requirements
- Burpsuite Pro
- Python 3
- Python Packages:
	- requests
	- json

## Usage
1. Generate an API key from the ``user options`` page in burpsuite.
2. Import PyBurp2

### Start a Scan:
```python3
startBurpScan("127.0.0.1:1337/", "LongAPIKey", "My.Domain.com", [("username", "password)])
```

### Get Scan Results:
```python3
getIssues("127.0.0.1:1337/", "LongAPIKey", "5")
```

## Future
- Add polling of a scan.
- Allow setting a detailed scope.
- Allow setting a configuration.
- Provide configuration from file.
- Use or create a resource pool
- Callback listener

## Contributing
Feel free to open an issue or PR on Github. The project is currently in early stages, so I'll be happy for the help.

## Credit
- Cheers to PortSwigger for all of the work going into BurpSuite 2.0.
- Thanks to Jake at Larconic Wolf, who's introduction to the API helped with working out Burps endpoint. https://laconicwolf.com/2018/08/27/exploring-the-burp-suite-api/
