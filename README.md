# GO-SPOOF

- GO-SPOOF provides the same functionality as the original portspoof (https://github.com/drk1wi/portspoof) with a few additional features. 


# Setup!

Portspoof requires all traffic to be directed to a single port. 
Run either of the following commands to setup the iptables rule to redirect to port 4444:

```./src/goSpoof -sT 4444```

```sudo iptables -t nat -A PREROUTING -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports 4444```

After running, cd into the src directory.

```cd src```

The executable "goSpoof" should already exist in the directory - if not, rebuild it using the following: 

```go build -o goSpoof```

Run the executable

```./goSpoof```

Move it into bin using the following command: 

```cp ./goSpoof bin```

# HELP!

```
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
  -oS string
        start go-spoof on boot (default None)
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
  -v string
        be verbose (default None)
```
