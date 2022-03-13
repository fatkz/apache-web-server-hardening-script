# apache-web-server-hardening-script




> The main purpose of apache web server hardening is to configure your apache server in an easy way. 
> _For instructions on installation, see  [Installation]. I highly recommend you follow them._
## Installation

```sh
git clone https://github.com/fatkz/apache-web-server-hardening-script.git
cd apache-web-server-hardening-script
chmod +x installing.sh
pip3 install -r requirements.txt
```
## usage
````--mothod=````  types of methods
````--file=```` file path
```` --limit-expect=```` method banned 'yes' or 'no'
````--hide```` file banned 'yes' or 'no'
````--iframe```` Type yes to initialize iframe function

```sh
sudo python3 main.py  --method PUT POST --limit-expect=no --file={path} --hide=yes --iframe=yes 
```
* In the code block above, it blocks the other part of the underlying process that says ````--file=````.  Adding ````--iframe=```` yes or no blocks iframe tags with apache html mountains


```sh
sudo python3 main.py  --method PUT POST --limit-expect=yes --file={path} --hide=no iframe=yes
```
````--file=```` in the code block above determines which methods are blocked from the given path

