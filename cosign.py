from twisted.internet import defer, reactor

from autobahn.wamp.auth import compute_wcs
from autobahn.wamp.types import CallOptions
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner

from twisted.internet import reactor
import mnemonic
from pycoin.key import BIP32Node, Key
from pycoin.serialize import h2b #hexlify
from pycoin import ecdsa as pycoin_ecdsa
from getpass import getpass

import random, binascii, struct, requests

from pycoin.key import BIP32Node, Key
from pycoin import ecdsa as pycoin_ecdsa
from pycoin.encoding import sec_to_public_pair

import hashlib, hmac

import mnemonic
import random, binascii, struct, requests
from bitcoin.core.script import CScript, OP_CHECKMULTISIG
from bitcoin.base58 import CBase58Data
from bitcoin.wallet import P2SHBitcoinAddress, CBitcoinAddress
from bitcoin import SelectParams
from bitcoin.rpc import Proxy
import sys

SelectParams('testnet')


#TODO: Subaccounts with 3' branch
def validateGAAddr(result, wallet):

    if sys.version_info.major < 3:
        addrscript = CScript(binascii.unhexlify(result['script']))
    else:
        addrscript = CScript(binascii.unhexlify(result['script']))

    addrdata = [x for x in addrscript]

    assert(len(addrdata) == 5)
    
    if sys.version_info.major < 3:
        secondpkh = binascii.hexlify(addrdata[2])
    else:
        secondpkh = binascii.hexlify(addrdata[2])


    print("Second pubkey hash: %s" % secondpkh)
    
    m = addrdata[0]
    assert(m == 2)
    n = addrdata[3]
    assert(n==2)
    assert(addrdata[4] == OP_CHECKMULTISIG)

    hexsubkey = wallet.subkey(1).subkey(result['pointer']).public_copy().sec_as_hex()

    if sys.version_info.major < 3:
        addrfromapi = P2SHBitcoinAddress.from_redeemScript(CScript(binascii.unhexlify(result['script'])))
    else:
        addrfromapi = P2SHBitcoinAddress.from_redeemScript(CScript(binascii.unhexlify(result['script'])))

    assert(hexsubkey == secondpkh.decode('utf8'))

    return addrfromapi

def validateChange(result, wallet, path):
    prox = Proxy()
    tx = prox.decoderawtransaction(result['tx'])

    changeAddrKey = wallet.subkey(1).subkey(result['change_pointer']).public_copy().sec_as_hex()

def syncWallet(result, wallet, gaitwallet, path):

    hexprivkey = wallet.subkey(1).subkey(result['pointer']).wif()
    hexpubkey = wallet.subkey(1).subkey(result['pointer']).public_copy().sec_as_hex()
    tproxy = Proxy()

    GAKey = gaitwallet.subkey_for_path(path).subkey(result['pointer']).sec_as_hex()

    addrfromapi = P2SHBitcoinAddress.from_redeemScript(CScript(binascii.unhexlify(result['script'])))
    print(addrfromapi)

    #tproxy.call("importprivkey", hexprivkey, "", False)
    print(tproxy.call("createmultisig", 2, [GAKey, hexpubkey])['address'])

class GreenAddressClientProtocol(ApplicationSession):

    def __init__(self, token):
        super(GreenAddressClientProtocol, self).__init__()
        self.token = token

    def onConnect(self):
        """
        Implements :func:`autobahn.wamp.interfaces.ISession.onConnect`
        """
        self.join(
            u"realm1",
            authmethods=[u"wampcra"],
            authid=self.token
        )

    @defer.inlineCallbacks
    def onJoin(self, data):
        print('Welcome to GreenAddress mnemonic login example')
        print('\nThis script will login to GA in full mode')
        self.mnemonic_phrase = getpass('Please write your mnemonic phrase and press enter: ')
        self.mnemonic_phrase = "hotel helmet envelope amazing often proud scorpion myth shaft differ put expand equal scout piece million hair crater annual echo net eye middle replace"
        
        #Generate GA-side wallet path and key info
        GA_pubkey = binascii.unhexlify("036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3")
        GA_pair = sec_to_public_pair(GA_pubkey)
        GA_chaincode = binascii.unhexlify("b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04")
        gawallet = BIP32Node.BIP32Node('XTN', GA_chaincode, public_pair=GA_pair)
        if sys.version_info.major < 3:
            m = hmac.new(bytearray(self.mnemonic_phrase), bytearray('GreenAddress!!!'), hashlib.sha512)
        else:
            m = hmac.new(bytearray(self.mnemonic_phrase, 'utf-8'), bytearray('GreenAddress!!!', 'utf-8'), hashlib.sha512)
        gawalletpath = binascii.hexlify(m.digest())
        gawalletpath_bin = binascii.unhexlify(gawalletpath)
        gawalletpath_str = '/'.join(str(struct.unpack('!H', gawalletpath_bin[i*2:(i+1)*2])[0]) for i in range(32))

        # 1. Master wallet
        seed = mnemonic.Mnemonic.to_seed(self.mnemonic_phrase)
        self.wallet = BIP32Node.BIP32Node.from_master_secret(seed, 'XTN')
        # Change 'BTC' to 'XTN' for Testnet

        # 2. Login wallet
        path = '%X' % random.randint(0, 2**64-1)
        while len(path) < 16:
            path = '0' + path
        path_bin = binascii.unhexlify(path)
        path_str = '/'.join(str(struct.unpack('!H', path_bin[i*2:(i+1)*2])[0]) for i in range(4))
        wallet_login = self.wallet.subkey_for_path(path_str)

        # 3. Get challenge
        print('\nLogging in with mnemonic passphrase, requesting challenge')
        challenge = yield self.call(
            'com.greenaddress.login.get_challenge',
            self.wallet.bitcoin_address(),
            # disclose_me is required for authentication
            options=CallOptions(disclose_me=True)
        )

        # 4. Login
        signature = pycoin_ecdsa.sign(pycoin_ecdsa.generator_secp256k1, wallet_login.secret_exponent(), int(challenge))
        if signature[1]+signature[1] > pycoin_ecdsa.generator_secp256k1.order():
            signature = (signature[0], pycoin_ecdsa.generator_secp256k1.order() - signature[1])
        login_data = yield self.call(
            "com.greenaddress.login.authenticate",
            list(map(str, signature)),
            False,
            path,
            options=CallOptions(disclose_me=True)
        )

        if data and login_data:
            print(login_data)
            last_login = (login_data['last_login']['at'], login_data['last_login']['country'], login_data['last_login']['ip'])
            print('\nLogin successful! Last login on %s, from country %s, ip address: %s' % last_login)
        else: print('\nLogin failed')

        
        p2sh_addr = yield self.call(
                "com.greenaddress.vault.fund",
                return_pointer=True,
                options=CallOptions(disclose_me=True))

        print(p2sh_addr)
        validateGAAddr(p2sh_addr, self.wallet)

        syncWallet(p2sh_addr, self.wallet, gawallet, gawalletpath_str)
        '''
        balance = yield self.call(
                "com.greenaddress.txs.get_balance",
                options=CallOptions(disclose_me=True))
        print(balance)

        
        prep_tx = yield self.call(
                "com.greenaddress.vault.prepare_tx",
                rcpt_ad="2MtXwJyVCWLUmNeeNsQt958sV9658ZEpAdn",
                value="10000",
                add_fee='sender',
                priv_data={},
                options=CallOptions(disclose_me=True))
        print(prep_tx)
        '''
        

        reactor.stop()

    def onChallenge(self, challenge):
        if sys.version_info.major < 3:
            return compute_wcs(
                bytes(self.token), bytes(challenge.extra['challenge'])
            ).decode()
        else:
            return compute_wcs(
                bytes(self.token, 'utf-8'), bytes(challenge.extra['challenge'], 'utf-8')
            ).decode()

if __name__ == '__main__':
    factory = ApplicationRunner(
        u"wss://testwss.greenaddress.it/v2/ws/",
        u"realm1",
        # debug_wamp=True,  # optional; log many WAMP details
        # debug=True,  # optional; log even more details
    )

    token = requests.get('https://test.greenaddress.it/token/').text
    factory.run(
        make=lambda *args: GreenAddressClientProtocol(token)
    )

    #hotel helmet envelope amazing often proud scorpion myth shaft differ put expand equal scout piece million hair crater annual echo net eye middle replace
