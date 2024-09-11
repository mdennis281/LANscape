# LANscape
A python based local network scanner.

![screenshot](https://github.com/mdennis281/py-lanscape/raw/main/src/lanscape/static/img/readme1.png)

## Local Run
```sh
pip install lanscape
python -m lanscape
```

## Flags
 - `--port <port number>` port of the flask app (default: 5001)
 - `--nogui` run in web mode (default: false)
 - `--debug` verbose logging (default: false)

Examples:
```shell
python -m lanscape --debug
python -m lanscape --nogui --port 5002
```
