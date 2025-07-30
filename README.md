<div align="center">
<a href="https://blackhillsinfosec.com"><img width="100%" src="./img/banner.png" alt="GoSpoof Logo" /></a>
<hr>
  <a href="https://github.com/blackhillsinfosec/go-spoof/actions"><img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/blackhillsinfosec/go-spoof/.github%2Fworkflows%2Fgo.yml?style=flat-square"></a> 
  &nbsp;
  <a href="https://discord.com/invite/bhis"><img alt="Discord" src="https://img.shields.io/discord/967097582721572934?label=Discord&color=7289da&style=flat-square" /></a>
  &nbsp;
  <a href="https://github.com/blackhillsinfosec/go-spoof/graphs/contributors"><img alt="npm" src="https://img.shields.io/github/contributors-anon/blackhillsinfosec/go-spoof?color=yellow&style=flat-square" /></a>
  &nbsp;
  <a href="https://x.com/BHinfoSecurity"><img src="https://img.shields.io/badge/follow-BHIS-1DA1F2?logo=twitter&style=flat-square" alt="BHIS Twitter" /></a>
  &nbsp;
  <a href="https://x.com/BHinfoSecurity"><img src="https://img.shields.io/github/stars/blackhillsinfosec/go-spoof?style=flat-square&color=rgb(255%2C218%2C185)" alt="GoSpoof Stars" /></a>

<p class="align center">
<h4><code>GoSpoof</code> is a push torwards bringing cyber deceptive tooling back into your defensive toolkit. This tool was directly inspired by the tool portspoof.</h4>
</p>

<div align="center">
  <h4>
    <a target="_blank" href="https://www.blackhillsinfosec.com/go-spoof-a-tool-for-cyber-deception/" rel="dofollow"><strong>Blog Post</strong></a>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
    <a target="_blank" href="https://gospoof.github.io/" rel="dofollow"><strong>Docs</strong></a>
  </h4>
</div>
<hr>

<div align="left">

## Setup

Portspoof requires all traffic to be directed to a single port. 
Run either of the following commands to setup the iptables rule to redirect to port 4444:

```bash
./src/goSpoof -sT 4444
```

```bash
sudo iptables -t nat -A PREROUTING -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports 4444
```
Run the WebUI and Docker start up script

```bash
go run DockerSetup.go
```

For Docker you can run

```bash
docker build -t gospoof .
```
Then 

```bash
docker run --rm --network host --privileged gospoof (any flags you wish as normal)

```

For NON-Docker, After running iptable rules, cd into cmd and build the website

```bash
cd cmd
go run webui.go
cd gospoof
```

The executable "goSpoof" should already exist in the directory - if not, rebuild it using the following: 

```bash
go build -o goSpoof
```

Run the executable

```bash
./goSpoof
```

Move it into bin using the following command: 

```bash
cp ./goSpoof bin
```

## Usage and CLI Structure

```python
Usage of ./goSpoof:
  -D string
        run as daemon process (default None)
  -Y string
        load configuration from yaml file (default None)
  -fT string
        reset iptables (default None)
  -i string
        ip : Bind to a particular IP address (default if none specified, goSpoof will grab your IP)
  -l string
        file_path : log port scanning alerts to a file (default None)
  -p string
        port : bind to a particular PORT number (default "4444")
  -r string
        port range for iptables to redirect from. Format is (low port):(high port) Must be used with -sT arg (default "1:65535")
  -s string
        file_path : go-spoof service signature regex. file (default None)
  -sP string
        Provide a range of ports (1-10) or a list of ports 1,9,32, or a single port (default "1-65535")
  -sT string
        setup iptables to bind to a single port (bind to this port using -p). Specify specific range of ports to redirect FROM with -r (default None)
  -w string
        specify a number of seconds to wait between sending signatures. Significantly slows down scanning with -sV
  -v string
        be verbose (default None)
  -honey
      Use -honey Y to activate a Honeypot Mode. This will give you an attackers IP as well as the date and time of the attack and what payloads were sent. This is then saved in honeypot.log
  -t
      Assign a value 1-5 to thottle time for a scan 1 = 5 minutes and doubles through each level to 5 = 80 minutes
  -rg
      Tunnels an intruders attacks back at them. This is a stand alone flag NO OTHER flags should be used with Rubber glue. Saves the hash and plain text in a captures directory.
  -e 
      Excludes ports that are specified
  --boot
      Saves flags used and starts go-spoof as configured with said flags, on boot.
  -rm
      Removes all flags used on boot as well as the saved config file and deletes the gospoof.service. A complete fresh start
  --WebUI
      This launches the GoSpoof Command Center. To run the website without the entire GoSpoof tool running, simply cd .. then cd Web/Server then do node server.js. Open up a browser of your choice and go to http://localhost:3000
```

<div align="center">

Made with ❤️ by Black Hills Infosec
