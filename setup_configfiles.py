import os
import random
import string
import json
# dogecoin.conf

def get_random_alphaNumeric_string(stringLength=16):
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join((random.choice(lettersAndDigits) for i in range(stringLength)))

if __name__ == '__main__':
    print("This script will set up all required config files and directories for the reader service. If files already exist, they "+
          "will be renamed to xxx.bak.")
    # create dogecoin.conf
    dogeaddress = "DPsVStLw5XwU2H42wNj9nf9Un4AraDv71B"
    dcrpcuser = "reader" + get_random_alphaNumeric_string(stringLength=4)
    dcpass = get_random_alphaNumeric_string(stringLength=16)
    # test for existing file and rename.
    filename = os.path.join("dogecoin_service", "dogecoin.conf")
    print("setting up ", filename)
    if os.path.isfile(filename):
        os.rename(filename,filename+".bak")
    with open(filename, "w") as outf:
        outf.write("# dogcoin.conf for https://moringa.pub blockchain based publication register\n")
        outf.write("rpcallowip=::/0 # allow from everywhere because we don't know the IP of the docker host\n")
        outf.write("rpcuser="+ dcrpcuser+"\n")
        outf.write("rpcpassword="+ dcpass+"\n")
        outf.close()
    # create blockchainconf.json
    # test for existing file and rename.
    filename = os.path.join("reader", "blockchainconf.json")
    print("setting up ", filename)
    if os.path.isfile(filename):
        os.rename(filename,filename+".bak")
    with open(filename, "w") as outf:
        data = {"port": 22555, "user": dcrpcuser, "password": dcpass, "address": "DPsVStLw5XwU2H42wNj9nf9Un4AraDv71B",
                "dogehostname": "dogecoin", "ipfs":"/dns/ipfsd/tcp/5001/http"}
        json.dump(data, outf)
        outf.close()
    # the reader server will create local key files if they don't exist. They are not really important.
    filename = os.path.join("dogecoin_service", "dogecoindata")
    if not os.path.isdir(filename):
        print("creating directory "+ filename)
        os.mkdir(filename)
    else:
        print("directory %s already exists." %filename)
    filename = os.path.join("ipfsd", "ipfsdb")
    if not os.path.isdir(filename):
        print("creating directory "+ filename)
        os.mkdir(filename)
    else:
        print("directory %s already exists." %filename)
    print("All files have been set up. You may now start the system with 'docker-compose up'. Have fun!")