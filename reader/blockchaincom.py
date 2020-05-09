# This library handles all communication with the blockchain, using our dogecoin_OP_RETURN package
#
# Copyright (C) 2019 Ingo R. Keck
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as
#     published by the Free Software Foundation, either version 3 of the
#     License, or (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import nacl.encoding
import nacl.signing
import nacl.public
import nacl.utils
import op_return_dogecoin
import unittest
import json
import time
import os
import copy
import datetime

TESTNET = False

# load dogecoin config
doge = dict()
try:
    with open("readerconf.json", "r") as readerconf:
        doge = json.load(readerconf)
except FileNotFoundError:
    print("Please provide a readerconf.json file with port, user, password, hostname, and doge-address for dogecoin, " +
          "and multiaddress for ipfs demon" +
          "\n An example file will be generated now.")
    if not os.path.exists("readerconf.json"):
        with open("readerconf.json", "w") as readerconf:
            doge = {'port': 22555, 'user': 'username', 'password': '1234', 'address': 'DPsVStLw5XwU2H42wNj9nf9Un4AraDv71B',
                    'dogehostname': '127.0.0.1', "ipfs": "/dns/localhost/tcp/5001/http"}
            json.dump(doge, readerconf)
            readerconf.close()
        raise FileNotFoundError("readerconf.json not defined")

op_return_dogecoin.OP_RETURN_DOGECOIN_PORT = doge['port']
op_return_dogecoin.OP_RETURN_DOGECOIN_USER = doge['user']
op_return_dogecoin.OP_RETURN_DOGECOIN_PASSWORD = doge['password']
op_return_dogecoin.OP_RETURN_DOGECOIN_ADDRESS = doge['address']
op_return_dogecoin.OP_RETURN_DOGECOIN_IP = doge['dogehostname']


def load_encryptkey_file(filename='keyfile.json'):
    with open(filename, "r") as infile:
        obj = json.load(infile)
    private_key = None
    public_key = None
    if "private_key" in obj:
        private_key = nacl.public.PrivateKey(obj["private_key"], encoder=nacl.encoding.HexEncoder)
    if "public_key" in obj:
        public_key = nacl.public.PublicKey(obj["public_key"], encoder=nacl.encoding.HexEncoder)

    return private_key, public_key


def save_encryptkey_file(privatekey, filename):
    obj = dict()
    obj["private_key"] = privatekey.encode(encoder=nacl.encoding.HexEncoder).decode("utf8")
    obj["public_key"] = privatekey.public_key.encode(encoder=nacl.encoding.HexEncoder).decode("utf8")
    with open(filename, "w") as outfile:
        json.dump(obj, outfile)
    return True


def save_sigkey_file(signaturkey, filename):
    obj = dict()
    obj["signing_key"] = signaturkey.encode(encoder=nacl.encoding.HexEncoder).decode("utf8")
    obj["verify_key"] = signaturkey.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode("utf8")
    with open(filename, "w") as outfile:
        json.dump(obj, outfile)
    return True


def load_sigkey_file(filename='sigkeyfile.json'):
    with open(filename, "r") as infile:
        obj = json.load(infile)
    signing_key = nacl.signing.SigningKey(obj["signing_key"], encoder=nacl.encoding.HexEncoder)
    return signing_key


def generate_sigkey_file():
    """
    Generate new keys and save them locally. backs up old file
    :return: status from saving keys
    """
    mykey = create_signing_keys()
    if os.path.exists('sigkeyfile.json'):
        os.rename('sigkeyfile.json', time.strftime('%Y_%m_%d_%H_%M_%S_', ) + 'keyfile.json')
    r = save_sigkey_file(mykey, 'sigkeyfile.json')
    return r


def generate_encryptkey_file():
    """
    Generate new keys and save them locally. backs up old file
    :return: status from saving keys
    """
    mykey = create_encryption_keys()
    if os.path.exists('keyfile.json'):
        os.rename('keyfile.json', time.strftime('%Y_%m_%d_%H_%M_%S_', ) + 'keyfile.json')
    r = save_encryptkey_file(mykey, 'keyfile.json')
    return r


def create_encryption_keys():
    """
    Create public private key pair for encryption
    :return: created key
    """
    allkeys = nacl.public.PrivateKey.generate()
    # privkey = allkeys.sk
    # pubkey = allkeys.pk
    return allkeys


def create_signing_keys():
    """
    Create public private key pair for signatures
    :return: created key
    """
    allkeys = nacl.signing.SigningKey.generate()
    # pubkey = allkeys.verify_key
    return allkeys


def encrypt(privkey, pubkey, message):
    """
    Encrypt a message to the pubkey, using the privkey for authentication
    :param privkey:
    :param pubkey:
    :param message: message as bytes
    :return: encrypted message
    """
    if not isinstance(message, bytes):
        message.encode('utf8')
    cryptbox = nacl.public.Box(private_key=privkey, public_key=pubkey)
    encrypted = cryptbox.encrypt(message)
    return encrypted


def decrypt(privkey, pubkey, message):
    cryptbox = nacl.public.Box(private_key=privkey, public_key=pubkey)
    plaintext = cryptbox.decrypt(message)
    return plaintext


def sign(signing_key, message):
    if not isinstance(message, bytes):
        message.encode('utf8')
    signed = signing_key.sign(message)
    return signed


def verify_signature(verify_key, signature):
    try:
        message = verify_key.verify(signature)
    except nacl.exceptions.BadSignatureError:
        return False, None
    return True, message


def save_on_dogecoin(message, process="clear", privkey=None, signkey=None, pubkey=None,
                     dogeaddress=op_return_dogecoin.OP_RETURN_DOGECOIN_ADDRESS, verbose=False, testrun=False):
    """

    :param message:
    :param process: can be "clear", "sign", or "encrypt"
    :param privkey: private key for box encryption
    :param signkey: signature key for signature
    :param pubkey: public key for box encryption
    :param dogeaddress: the address where the TX should be sent
    :return:
    """
    if verbose:
        print("address: %s" % dogeaddress)
    # encrypt message
    # split up in xxbytes parts
    if not privkey:
        if process == "encrypt":
            # first get keys
            privkey, pubkey = load_encryptkey_file()
    messagelength = op_return_dogecoin.OP_RETURN_MAX_BYTES - 10
    if not isinstance(message, bytes):
        if isinstance(message, str):
            message = message.encode('utf8')
        else:
            raise TypeError
    if len(message) > (messagelength * 10):
        print("Message should be smaller than %d bytes" % (messagelength * 10))
        raise MemoryError
    # encrypted = encrypt(privkey=privkey, pubkey=pubkey, message=message).decode('latin1')
    if process == 'clear':
        encrypted = message
    elif process == 'encrypt':
        encrypted = encrypt(privkey=privkey, pubkey=pubkey, message=message)
    elif process == 'sign':
        encrypted = sign(signing_key=signkey, message=message)
    else:
        raise ValueError('Unknown process type: %s' % process)
    # MOxxxyz: MO, xxx: random identifier, y message index, z max index
    # xxx = os.urandom(4).decode('latin1')
    xxx = os.urandom(4)
    max_index = int(len(encrypted) / messagelength) - 1  # 0 is first
    if len(encrypted) % messagelength > 0:
        max_index += 1
    if len(encrypted) > messagelength:
        encrypt_list = []
        _ = 0
        for _ in range(int(len(encrypted) / messagelength)):
            pos = '%d%d:' % (_, max_index)
            # encrypt_list.append('MO' + xxx + str(pos) + encrypted[_ * messagelength:(_ + 1) * messagelength])
            encrypt_list.append(b'MO' + xxx + pos.encode('latin1') + encrypted[_ * messagelength:(_ + 1) * messagelength])
        if len(encrypted) % messagelength > 0:
            _ += 1
            pos = '%d%d:' % (_, max_index)
            # encrypt_list.append('MO' + xxx + str(pos) + encrypted[_ * messagelength:])
            encrypt_list.append(b'MO' + xxx + pos.encode('utf8') + encrypted[_ * messagelength:])
    else:
        encrypt_list = [encrypted]
    # create dogecoin transactions
    # put it on dogecoin
    txlist = []
    for m in encrypt_list:
        print('sent Message:')
        print(m)
        if testrun:
            print("Message is: %s" % m)
            newtx = ""
        else:
            newtx = op_return_dogecoin.OP_RETURN_send(send_address=dogeaddress, send_amount=1, metadata=m,
                                                      testnet=TESTNET)
        if isinstance(newtx, dict):
            if 'error' in newtx:
                if newtx['error']:
                    print(newtx['error'])
                    raise ValueError
        txlist.append(newtx)
    return txlist


def retrieve_from_dogecoin(dogeaddress, process="clear", startnumber=0, startdate=None, stopdate=None, privkey=None,
                           pubkey=None, verifykey=None, VERBOSE=False):
    """
    Searches the blockchain for op_return transactions, decrypts them and
    returns them as tuple (message, timestamp)
    :param dogeaddress: Dogecoin address to watch
    :param process: what should the function do?
    :param startnumber: Start with that message number
    :param startdate: Start looking for transactions at that date
    :param stopdate: Stop looking for transactions at that date
    :param VERBOSE: if True print out what you are doing
    :return: list of decrypted messages for the dogeaddress as ("message", timestamp)
    """
    if VERBOSE:
        print("Dogecoin address: %s, loading keys..." % dogeaddress)
    # first get keys
    if not privkey:
        privkey, pubkey = load_encryptkey_file()
    # retrieve transactions
    if VERBOSE:
        print("get all transactions starting with %d" % startnumber)
    all_tx = get_transactions_dogecoin(dogeaddress, startnumber=startnumber)
    # extract op_return for transactions with the same times
    messages = dict()
    for tx in all_tx:
        if VERBOSE:
            print("looking at transaction %s " % tx['txid'])
        if startdate:
            if tx['time'] < startdate:
                continue
        if stopdate:
            if tx['time'] > stopdate:
                continue
        if VERBOSE:
            print("Get message from transaction %s " % tx['txid'])
        message = op_return_dogecoin.OP_RETURN_get(tx['txid'], testnet=TESTNET)
        if not message:
            continue
        # sort for time, then for reference
        # get actual time with datetime.datetime.fromtimestamp(tx['time'] or tx['blocktime'] )
        # sort for xxx reference
        # KUxxxyz:data KU Kubrik, xxx: random identifier, y message index, z max index
        # convert to latin1
        # try:
        #    message['op_return'] = message['op_return'].decode('utf8')
        #    # message['op_return'] = message['op_return'].decode('latin1')
        # except:
        #    # probably not one of ours
        #    continue
        # if not message['op_return'][8] == ':':
        if not message['op_return'][8] == 58:
            # not one of ours
            continue
        # print('got message: ')
        # print(message['op_return'])
        xxx = message['op_return'][2:6]
        txtime = round(tx['time'] / 1800)  # put all messages within 1800sec together
        if txtime in messages:
            if xxx in messages[txtime]:
                messages[txtime][xxx].append((message['op_return'], tx['time'], tx['txid']))
            else:
                messages[txtime][xxx] = [(message['op_return'], tx['time'], tx['txid'])]
        else:
            messages[txtime] = dict()
            messages[txtime][xxx] = [(message['op_return'], tx['time'], tx['txid'])]
    # combine them
    # we can get attacked with additional messages. We need to test them to find the right ones
    decrypted_msg = list()
    for txtime in messages:
        # all messages in one time frame
        for xxx in messages[txtime]:
            # all messages with same xxx code
            # possible_msg = list()
            allmsg = dict()
            alltimes = dict()
            alltx = dict()
            for mesgtx in messages[txtime][xxx]:
                msg = mesgtx[0]
                # we can have multiple lengths
                # MOxxxyz: MO, xxx: random identifier, y message index, z max index
                try:
                    if msg[7] in allmsg:
                        if int(msg[6]) in allmsg[msg[7]]:
                            allmsg[msg[7]][int(chr(msg[6]))].append(msg[9:])
                        else:
                            allmsg[msg[7]][int(chr(msg[6]))] = [msg[9:]]
                    else:
                        allmsg[msg[7]] = dict()
                        allmsg[msg[7]][int(chr(msg[6]))] = [msg[9:]]
                        alltimes[msg[7]] = mesgtx[1]  # we take the first time as reference
                        alltx[msg[7]] = mesgtx[2] # we taḱe the first txid as txid
                except:
                    continue
            # now get all permutations for a given length
            possible_msg = list()
            for l in allmsg:
                newmsg = list()
                newtime = alltimes[l]
                newtx = alltx[l]
                for p in range(len(allmsg[l])):
                    # make a copy of the tree so far for later
                    newtree_orig = list(newmsg)
                    try:
                        for idx, m in enumerate(allmsg[l][p]):
                            newtree = list(newtree_orig)
                            if idx > 0:
                                # print(l, p, m)
                                if len(newtree) == 0:
                                    newtree.append(m)
                                else:
                                    for i in range(len(newtree)):
                                        newtree[i] += m
                                # add new tree
                                for n in newtree:
                                    newmsg.append(n)
                            else:
                                if len(newmsg) == 0:
                                    newmsg.append(m)
                                else:
                                    for i in range(len(newmsg)):
                                        newmsg[i] += m
                                        # print(l, p, m)
                    except:
                        # fail silently for messages that do not have all positions
                        pass
                for m in newmsg:
                    possible_msg.append((m, newtime, newtx))
            # decrypt all
            for message in possible_msg:
                try:
                    if VERBOSE:
                        print("trying to decrcypt: ", message[0])
                    if process == 'clear':
                        msg = message[0]
                    elif process == 'encrypt':
                        msg = decrypt(message=message[0], privkey=privkey, pubkey=pubkey)
                        # msg = decrypt(message=message[0].encode('latin1'), privkey=privkey, pubkey=pubkey)
                    elif process == 'sign':
                        if isinstance(verifykey, str):
                            verifykey = nacl.signing.VerifyKey(verifykey, encoder=nacl.encoding.HexEncoder)
                        result, msg = verify_signature(verify_key=verifykey, signature=message[0])
                        if not result:
                            if VERBOSE:
                                print("signature not valid in ", message[0])
                            continue
                    else:
                        raise ValueError('Unknown process type: %s' % process)
                    # add valid ones to decrypted_msg
                    decrypted_msg.append((msg, message[1], message[2]))
                except Exception as e:
                    # we ignore bad messages
                    if VERBOSE:
                        print("was not valid :-(", e)
                    pass
            # print(possible_msg)
    # return them
    return decrypted_msg


def add_watchadress_dogecoin(dogeaddress, label='reprowatch', rescan=True):
    """
    Adds an address as address to watch to dogecoin
    :param dogeaddress: address that should be added
    :return: True if all went well
    """
    # first test if address is watched
    addressgroups = op_return_dogecoin.OP_RETURN_dogecoin_cmd('listaddressgroupings', testnet=TESTNET)
    createaddress = True
    for ag in addressgroups:
        for ad in ag:
            if ad[0] == dogeaddress:
                createaddress = False
                break
    if createaddress is True:
        # add address as watchonly in wallet
        try:
            result = op_return_dogecoin.OP_RETURN_dogecoin_cmd('importaddress', TESTNET, dogeaddress, label, str(rescan))
        except BaseException as e:
            print("could not add address %s as watch-only: %s" % (dogeaddress,e))
            return False
    return True


def get_transactions_dogecoin(dogeaddress, startnumber=0, maxnumber=None):
    """
    Get list of transactions for a given dogecoin address
    :param dogeaddress: Dogecoin Address
    :param startnumber: Start with that transaction number
    :param maxnumber: only retrieve that amount of transactions
    :return: list of transaction IDs
    """
    # we need to do that with an address that is watched, so make sure it is in the wallet
    add_watchadress_dogecoin(dogeaddress)
    # now, get all the transactions
    txlist = list()
    tx_no = 50
    tx_start = startnumber
    txid_list = list()
    while True:
        result = op_return_dogecoin.OP_RETURN_dogecoin_cmd('listtransactions', TESTNET, "*", tx_no, tx_start, True)
        # result = op_return_dogecoin.OP_RETURN_dogecoin_cmd('listtransactions', False)
        if not result:
            break
        for tx in result:
            if 'address' in tx:
                # print(tx['address'])
                # print(tx)
                if tx['address'] == dogeaddress:
                    if tx['txid'] not in txid_list:
                        # print(datetime.datetime.fromtimestamp(tx['time']))
                        txlist.append(copy.deepcopy(tx))
                        txid_list.append(tx['txid'])
        tx_start += tx_no
        if maxnumber:
            if tx_start - startnumber > maxnumber:
                break
    return txlist


def get_tx(txid):
    """
    Retrieve the transaction txid from the blockchain. Will fail if it is not for a watched address.
    :param txid: transaction id
    :return: decomposed transaction
    """
    # test if txid is valid
    test = op_return_dogecoin.OP_RETURN_hex_to_bin(txid)  # returns None if failes
    if test:
        transaction = op_return_dogecoin.OP_RETURN_get_mempool_txn(txid, testnet=TESTNET)
    else:
        transaction = None
    return transaction


# tests
class TestCrypto(unittest.TestCase):

    def test_createkeys(self):
        """
        Test if we can create and save keys and load keys
        :return:
        """
        aa = create_encryption_keys()
        b = save_encryptkey_file(aa, "test.json")
        c = load_encryptkey_file("test.json")
        assert aa == c[0]
        assert aa.public_key == c[1]
        aa = create_signing_keys()
        b = save_sigkey_file(aa, "test.json")
        c = load_sigkey_file("test.json")
        assert aa == c

    def test_encryption(self):
        privkey1 = create_encryption_keys()
        privkey2 = create_encryption_keys()
        mymessage = "halloöäß".encode('utf8')
        # myboxa = nacl.public.Box(private_key=privkey1, public_key=privkey2.public_key)
        # myboxb = nacl.public.Box(private_key=privkey2, public_key=privkey1.public_key)
        encrypted = encrypt(privkey=privkey1, pubkey=privkey2.public_key, message=mymessage)
        plaintext = decrypt(privkey=privkey2, pubkey=privkey1.public_key, message=encrypted)
        # print(message, encrypted, plaintext)
        assert plaintext == mymessage

    def test_signature(self):
        mysigkey = create_signing_keys()
        othersigkey = create_signing_keys()
        myverifykey = mysigkey.verify_key
        mymessage = "halloöäß".encode('utf8')
        signed = sign(mysigkey, mymessage)
        aa, r = verify_signature(myverifykey, signed)
        assert aa is True
        assert r == mymessage
        aa, r = verify_signature(othersigkey.verify_key, signed)
        assert aa is False
        assert r is None
        aa, r = verify_signature(myverifykey, signed + b'34')
        assert aa is False
        assert r is None
        mysigkey = create_signing_keys()
        myverifykey = mysigkey.verify_key
        aa, r = verify_signature(myverifykey, signed)
        assert aa is False
        assert r is None


# try to load key file


if __name__ == '__main__':
    # we can do a full test that actually costs coins, or a reduced test that only reads
    # messages from the chain
    try:
        keys = load_encryptkey_file()
    except FileNotFoundError:
        print("local key file not found. We will create a new one.")
        if not os.path.exists('keyfile.json'):
            generate_encryptkey_file()
    # generate_encryptkey_file()
    answer = input('Do Dogecoin test? "full" will cost coins for a message! [y,n, f=full]')
    ad = op_return_dogecoin.OP_RETURN_DOGECOIN_ADDRESS
    processes = ['clear', 'sign', 'encrypt']
    if answer == 'f':
        if ad:
            add_watchadress_dogecoin(ad)
            privk, pubk = load_encryptkey_file()
            signkey = load_sigkey_file()
            verifykey = signkey.verify_key
            for p in processes:
                message = p + " - " + 2 * "testäöüß–– " + datetime.datetime.now().isoformat()
                txlist = save_on_dogecoin(message, process=p, privkey=privk, pubkey=pubk, signkey=signkey,
                                          dogeaddress=ad)
                print(txlist)
            # give it 10 s to settle
            time.sleep(10)
            # retrieve it again
    if (answer == 'f') | (answer == 'y'):
        if ad:
            add_watchadress_dogecoin(ad)
            # message = 20 * "test"
            privk, pubk = load_encryptkey_file()
            signkey = load_sigkey_file()
            verifykey = signkey.verify_key
            for p in processes:
                print("testing process", p)
                messages = retrieve_from_dogecoin(dogeaddress=ad, process=p, privkey=privk, pubkey=pubk,
                                                  verifykey=verifykey, VERBOSE=False)
                print(messages)
                for m in messages:
                    try:
                        print(m[0].decode('utf8'))
                        print(m[0].decode('latin1'))
                    except:
                        pass
