# SoftOffload Agent

SoftOffload Agent is a Click-Based management module designed for wireless association and client monitoring on WiFi and cellular access ponits. It cooperates with the [SoftOffload Master](https://github.com/TKTL-SDN/SoftOffload-Master) and the [client extension](https://github.com/TKTL-SDN/SoftOffload-Client) to provide SDN-based wireless services.

Our agent logic is implemented mainly by using a custom Click element called [sdnagent](https://github.com/TKTL-SDN/SoftOffload-Agent/tree/eit-sdn/elements/local/agent/). To facilitate system building, we merge all the rest [Click codes](https://github.com/kohler/click) in this repo.

## Usage

### Build

    $ git clone https://github.com/TKTL-SDN/SoftOffload-Agent.git
    $ cd SoftOffload-Agent

    # our current agent does not support kernel mode
    # you may choose to disable linux kernel mode to speed up the building

    $ ./configure --enable-wifi --enable-local (--disable-linuxmodule)
    $ make

### Generate custom configuration for your system

Change agent configuration [agent.click](https://github.com/TKTL-SDN/SoftOffload-Agent/tree/eit-sdn/conf/local-agent) for your system.

We provide a [script](https://github.com/TKTL-SDN/SoftOffload-Agent/tree/eit-sdn/conf/local-agent/agent-config-generator.py) to help you generate suitable config file quickly for your system.

```
$ cd SoftOffload-Agent/conf/local-agent/

# read our help instruction on parameter setting    
$ ./agent-config-generator.py -h

# run the script with suitable arguments to generate config file
$ ./agent-config-generator.py [your args...] > agent.click
```

You can find instruction about parameters with this script when you run it, or you can use `-h` to check help info.


### Run

    # run Click in the userlevel
    sudo ./userlevel/click conf/local-agent/agent.click

## Licence

This project is licensed under the [Click LICENSE](https://github.com/TKTL-SDN/SoftOffload-Agent/tree/eit-sdn/LICENSE) (based on an MIT license).

