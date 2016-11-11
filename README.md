Internet Group Management Protocol Version 3   
As described by RFC 3376, RFC 2236 and RFC 1112.

Implemented using C++ and click modular router.

# Instructions  
After cloning this project to a preferred location we will have to setup two symbolic links inside click-2.0.1 from scripts and elements/local directories to prevent duplication of files. To do so we will use:

cd click-2.0.1/  
ln -s ../../igmpv3/scripts/IGMPv3 scripts/IGMPv3  
ln -s ../../../igmpv3/elements/local/IGMPv3 elements/local/IGMPv3  

Make sure the path to your cloned repository is correct. When using relative path you need to take the viewpoint of click-2.0.1/scripts/ and click-2.0.1/elements/local/ respectively. In the example above we've cloned the repository right next to click-2.0.1 directory.

You can work with the files in both locations now! 

# Demonstrations
We will gather several examples inside subdirectories at `scripts/IGMPv3/tests/`  
You're supposed to run .click files with `./userlevel/click -p 10000 scripts/IGMPv3/tests/example-name.click`  
In another terminal run the respective command `./scripts/IGMPv3/tests/example-name.sh | telnet 127.0.0.1 10000`  
This will invoke our handlers on the click script. To verify the results use `wireshark example-name.dump`  

Example files | Comments
--- | ---
`joins/report-default-values` | generates a Join IGMP Report packet for group address 225.1.1.1 with **default values** 
`joins/report-exclude-mode` | another report message for **given** socket, interface, group and sources list in **EXCLUDE** mode
`joins/report-include-mode` | another report message for **given** socket, interface, group and sources list in **INCLUDE** mode

# Authors
Eduard Besjentsev  
Nishchal Shrestha
