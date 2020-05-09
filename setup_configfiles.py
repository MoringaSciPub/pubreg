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
    # find user id
    uid = os.getuid()
    print("We will use your user id %d for the service users in the docker files. If you do not like this, "
          "please change the values in the Dockerfiles.")
    filename = os.path.join("dogecoin_service", "Dockerfile")
    print("Changing UID to %d in %s" %(uid, filename))
    with open(filename, 'r') as file:
        data = file.read().replace('ENV USERID 1000', 'ENV USERID '+str(uid))
        file.close()
    os.rename(filename, filename+'.bak')
    with open(filename, 'w') as file:
        file.write(data)
        file.close()
    filename = os.path.join("ipfsd", "Dockerfile")
    print("Changing UID to %d in %s" % (uid, filename))
    with open(filename, 'r') as file:
        data = file.read().replace('ENV USERID 1000', 'ENV USERID ' + str(uid))
        file.close()
    os.rename(filename, filename + '.bak')
    with open(filename, 'w') as file:
        file.write(data)
        file.close()
    filename = os.path.join("reader", "Dockerfile")
    print("Changing UID to %d in %s" % (uid, filename))
    with open(filename, 'r') as file:
        data = file.read().replace('ENV USERID 1000', 'ENV USERID ' + str(uid))
        file.close()
    os.rename(filename, filename + '.bak')
    with open(filename, 'w') as file:
        file.write(data)
        file.close()
    filename = os.path.join("docker-compose.yml")
    print("Changing UID to %d in %s" % (uid, filename))
    with open(filename, 'r') as file:
        data = file.read().replace('user: "1000', 'user: "' + str(uid))
        file.close()
    os.rename(filename, filename + '.bak')
    with open(filename, 'w') as file:
        file.write(data)
        file.close()
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
    filename = os.path.join("reader", "readerconf.json")
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
    print("All files have been set up. You may now start the system with 'docker-compose up --build' and connect " +
          "to the server at http://localhost:8080. Have fun!")