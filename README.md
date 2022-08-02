[![Docker Image CI](https://github.com/MoringaSciPub/pubreg/actions/workflows/docker-image.yml/badge.svg)](https://github.com/MoringaSciPub/pubreg/actions/workflows/docker-image.yml)

# Moringa Science Publishing Blockchain Publication Registry

This repository hosts our blockchain (Dogecoin :-) ) based publication registry. 
You can see it in action at https://pubreg.moringa.pub/

## Requirements 
To run your own node, you need:
* docker
* a good internet connection (50GB for the initial blockchain download, then mostly depending on the IPFS setup - 
  to keep network use low we use the dhtclient setting and low numbers for connections)
* 1 core for dogecoin and ipfs
* roughly 50Gb disk space (as of 2020-05-01) for the dogecoin chain.

## Install
Clone this repository. Then run

```[bash]
python3 setup_configfiles.py
```

This will create a unique local configuration for you with random username and password for the dogecoin rpc. 
It also will set the containers to run with your user account. 

After this setup is complete, you can start the system with 
```[bash]
docker-compose up --build
```

And after a short while you should be able to access the registry at http://localhost:8080/ or http://0.0.0.0:8080/

It will take some time till the blockchain is loaded (usually a few days) and the registry is up to date.

## Why Should I Run A Node

Each node is set to keep a copy of our publications. So with running your node, you help us keeping our publications
open and available. Also you are running a full dogecoin node, which is good for your karma.

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.
 
You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
