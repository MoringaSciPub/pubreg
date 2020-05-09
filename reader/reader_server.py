#     Copyright (C) 2020  Ingo Keck (ingokeck@ingokeck.de)
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published
#     by the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
import datetime
import logging
import os
import pickle
import time

import bottle
import ipfshttpclient
from bs4 import BeautifulSoup

import blockchaincom

global DB
global VERBOSE

#ipfsaddress = "/dns/localhost/tcp/5001/http"  # for standalone
ipfsaddress = "/dns/ipfsd/tcp/5001/http"  # for docker-compose
ipfsaddress = blockchaincom.doge["ipfs"]
app = bottle.Bottle()
template_path = "pages/"
staticpath = "static/"
db_file_name = "publications.pickle"
dogcoin_address = "DPsVStLw5XwU2H42wNj9nf9Un4AraDv71B"
verify_key = "22eea0792b1bd631028e3a818f03dbbb87a7ef6fbe8562179066432853d6f1e5"
VERBOSE = True
ipfs_known = list()
lastchange = ''
time_to_reload_db = datetime.timedelta(hours=1)

def load_db():
    with open(db_file_name, 'r') as infile:
        _DB = pickle.load(infile)
    return _DB

def save_db(myDB):
    with open(db_file_name, 'wb') as outfile:
        pickle.dump(myDB, outfile)

def retrieve_messages():
    global verify_key
    global dogcoin_address
    global VERBOSE
    newmessages = blockchaincom.retrieve_from_dogecoin(dogeaddress=dogcoin_address, process="sign", startnumber=0, startdate=None, stopdate=None, privkey=None,
                           pubkey=None, verifykey=verify_key, VERBOSE=VERBOSE)
    return newmessages

def pin_DB(mydb):
    """
    Pin all IPFS thingies in the DB
    :param mydb: DB object
    :return: list of pinned ipfs hashes
    """
    # get all ipfs pins
    with ipfshttpclient.connect(addr=ipfsaddress) as client:
        pins = client.pin.ls(type="all")
        pinlist = [i for i in pins["Keys"].keys()]
        # pin the ones that are not pinned already
        new_pins = list()
        for i in mydb:
            if i['ipfs'] not in pinlist:
                if VERBOSE:
                    logging.warning("pinning: %s" %i['ipfs'])
                _ = client.pin.add(i['ipfs'])
                new_pins.append(i['ipfs'])
            if i['ipfsmeta'] not in pinlist:
                if VERBOSE:
                    logging.warning("pinning: %s" %i['ipfsmeta'])
                _ = client.pin.add(i['ipfsmeta'])
                new_pins.append(i['ipfsmeta'])

    if len(new_pins)==0:
        if VERBOSE:
            logging.warning("no hashes needed pinning")
    return new_pins



def list_publications(messages):
    global verify_key
    global dogcoin_address
    global VERBOSE
    DB = list()
    with ipfshttpclient.connect(addr=ipfsaddress) as client:
        for message in messages:
            if isinstance(message[0], bytes):
                m = message[0].decode('utf8')
            else:
                m = message[0]
            mtime = datetime.datetime.utcfromtimestamp(message[1])
            mtx = message[2]
            # retrieve object from IPFS
            if VERBOSE:
                logging.warning("retrieving %s from IPFS..." %m)
            stuff = client.get_json(m)
            ipfsref = stuff['ipfsref']
            if VERBOSE:
                logging.info(stuff)
            soup = BeautifulSoup(stuff['DC'], features="html.parser")
            # get all metas
            metalist = soup.find_all("meta")
            authors = ""
            title = ""
            uri = ""
            dcdate = ""
            for meta in metalist:
                if meta.attrs['name'] == 'DC.Creator.PersonalName':
                    authors += meta.attrs['content'] + " ,"
                if meta.attrs['name'] == 'DC.Title':
                    title = meta.attrs['content']
                elif meta.attrs['name'] == 'DC.Identifier.URI':
                    uri = meta.attrs['content']
                elif meta.attrs['name'] == "DC.Date.created":
                    dcdate = meta.attrs['content']
            if len(authors)>0:
                authors = authors[:-1]
            DB.append({"author":authors, "title":title, "url":uri, "date":dcdate, "ipfs": ipfsref, "ipfsmeta": m,"meta":stuff, "txtime":mtime, "txid":mtx})
    return DB

def create_display_db(myDB):
    display_db = list()
    for item in myDB:
        author = item["author"]
        title = '<a href="'+item["url"]+'">'+item["title"]+"</a>"
        url = '<a href="https://ipfs.io/ipfs/'+item["url"]+'" class="break">'+item["url"]+"</a>"
        ipfs = '<a href="https://ipfs.io/ipfs/'+item["ipfs"]+'" class="break">'+item["ipfs"]+"</a>"
        date = item["date"]
        txid = '<a href="/api/get_tx/'+item["txid"]+'" class="break">'+item["txid"]+'</a>'
        display_db.append({"author":author, "title":title, "url":url, "ipfs":ipfs, "date":date, "txid":txid})
    return display_db

#@app.route('/hello')
#def hello():
#    return "Hello World!"

@app.route('/')
def index():
    # this is the page where all publications are listed
    # update db if to old
    global DB
    global lastchange
    if datetime.datetime.now()-lastchange > time_to_reload_db:
        if VERBOSE:
            logging.warning("old database, updating")
        messages = retrieve_messages()
        DB = list_publications(messages)
        if VERBOSE:
            logging.info(DB)
    #DB=[{'author':"Albert Einstein", "title":"About the universe", "date": "today", "ipfs":"asdsddsad"}]
    return bottle.template(os.path.join(template_path, "index.html"), pub_list=create_display_db(DB))

@app.route('/api/get_tx/<tx>')
def get_tx(tx):
    # check validity of tx
    if len(tx)!=64:
        return bottle.HTTPResponse(status=400, body="Bad tx: "+tx)
    try:
        _ = int(tx, base=16)
    except:
        return bottle.HTTPResponse(status=400, body="Bad tx: "+tx)
    # all clear, return tx object
    try:
        tx = blockchaincom.get_tx(tx)
    except:
        return bottle.HTTPResponse(status=404, body="Not found: "+tx)
    return tx

@app.route('/static/<filepath:path>')
def server_static(filepath):
    """Serve static files from the staticpath directroy (usually static)"""
    return bottle.static_file(filepath, root=os.path.join(os.path.dirname(os.path.realpath(__file__)), staticpath))

@app.route('/favicon.ico')
def favicon():
    return bottle.static_file("favicon.ico", root=os.path.join(os.path.dirname(os.path.realpath(__file__)), staticpath))

if __name__ == '__main__':
    if not os.path.exists('keyfile.json'):
        logging.warning("Generating encrypt key file")
        blockchaincom.generate_encryptkey_file()
    if not os.path.exists('sigkeyfile.json'):
        logging.warning("Generating signature key file")
        blockchaincom.generate_sigkey_file()
    flag = True
    while flag:
        try:
            messages = retrieve_messages()
            with ipfshttpclient.connect(addr=ipfsaddress) as client:
                pins = client.pin.ls(type="all")
                logging.warning(pins)
                DB = list_publications(messages)
            flag = False
        except:
            if VERBOSE:
                logging.warning("waiting 20s for dogecoin or IPFS")
            time.sleep(20)
    #DB = list_publications(messages)
    lastchange = datetime.datetime.now()
    save_db(DB)
    logging.warning(pin_DB(DB))
    flag = True
    while flag:
            try:
                bottle.run(app, host='0.0.0.0', port=8081)
            except:
                continue
