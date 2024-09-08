Remove-Item -Path .\dist\* -Recurse -Force
py -m pip install --upgrade pip
py -m pip install --upgrade build
py -m build
py -m pip install --upgrade twine
py -m twine upload --repository pypi dist/*