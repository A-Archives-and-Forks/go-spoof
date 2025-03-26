![logo](./img/gospoof.png)
# GO-SPOOF
GO-SPOOF is a recreation of the cyber deception tool [portspoof](https://github.com/drk1wi/portspoof). GO-SPOOF provides the same features as portspoof with some upgrades to functionality and reliability.

## Setup

Portspoof requires all traffic to be directed to a single port. 
Run either of the following commands to setup the iptables rule to redirect to port 4444:

```bash
./src/goSpoof -sT 4444
```

```bash
sudo iptables -t nat -A PREROUTING -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports 4444
```

After running, cd into the src directory.

```bash
cd src
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
```
Owned by Black Hills Infosec
Created by her3tic and redwingblackbird
