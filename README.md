# SoftOffload Agent

SoftOffload Agent is a Click-Based management module designed for wireless association and client monitoring on WiFi and cellular access ponits. It cooperates with the [SoftOffload Master](https://github.com/TKTL-SDN/SoftOffload-Master) and the [client extension](https://github.com/TKTL-SDN/SoftOffload-Client) to provide SDN-based wireless services.

Our agent logic is implemented mainly by using a custom Click element called [sdnagent](https://github.com/TKTL-SDN/SoftOffload-Agent/tree/eit-sdn/elements/local/agent/). To facilitate system building, we merge all the rest [Click codes](https://github.com/kohler/click) in this repo.

# Usage

## Build

    git clone https://github.com/TKTL-SDN/SoftOffload-Agent.git
    cd SoftOffload-Agent

    # our current agent does not support kernel mode
    # you may choose to disable linux kernel mode to speed up the building

    ./configure --enable-wifi --enable-local (--disable-linuxmodule)
    make

## Generate custom configuration for your system

Change agent [configuration](https://github.com/TKTL-SDN/SoftOffload-Agent/tree/eit-sdn/conf/local-agent/agent.click) for your system.

We will add a config generator script, and explain it later

## Run

    # run Click in the userlevel
    sudo ./userlevel/click conf/local-agent/agnet.click

# Licence

This project is licensed under the Click LICENSE (based on an MIT license).


