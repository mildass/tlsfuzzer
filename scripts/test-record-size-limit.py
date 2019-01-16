# Author: Hubert Kario, (c) 2015-2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain, islice

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        SetMaxRecordSize, SetPaddingCallback, ResetHandshakeHashes, \
        Close, ResetRenegotiationInfo, ch_cookie_handler
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        gen_srv_ext_handler_record_limit, ExpectEncryptedExtensions, \
        ExpectCertificateVerify, ExpectNewSessionTicket, \
        srv_ext_handler_supp_vers, gen_srv_ext_handler_psk, \
        srv_ext_handler_key_share, ExpectHelloRetryRequest
from tlsfuzzer.helpers import key_share_ext_gen, RSA_SIG_ALL, \
        psk_session_ext_gen, psk_ext_updater, key_share_gen
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName, TLS_1_3_DRAFT, SignatureScheme, \
        PskKeyExchangeMode
from tlslite.extensions import RecordSizeLimitExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
        PskKeyExchangeModesExtension, TLSExtension, ClientKeyShareExtension
from tlslite.utils.compat import compatAscii2Bytes


version = 1


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (excluding \"sanity\" tests)")
    print(" --expect-size  size to expect from server (+1 for TLS 1.3), 2^14")
    print("                by default")
    print(" --supported-groups expect the server to send supported_groups")
    print("                extension in EncryptedExtensions in TLS 1.3")
    print(" --hrr-supported-groups expect the server to send supported_groups")
    print("                extension in EncryptedExtension in HRR handshake")
    print("                in TLS 1.3")
    print(" --reply-AD-size size in bytes of the server reply (Application Data)")
    print(" --cookie       expect server to send cookie extension in Hello")
    print("                Retry Request message")
    print(" --request      the request to send to server, HTTP/1.0 GET by")
    print("                default. Needs to include the two new lines for")
    print("                HTTP requests")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expect_size = 2**14
    supported_groups = False
    hrr_supported_groups = False
    reply_size = None
    cookie = False
    request = b"GET / HTTP/1.0\r\n\r\n"

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:",
                               ["help", "expect-size=",
                                "supported-groups", "reply-AD-size=",
                                "cookie", "hrr-supported-groups",
                                "request="])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '--expect-size':
            expect_size = int(arg)
        elif opt == '--supported-groups':
            supported_groups = True
        elif opt == '--hrr-supported-groups':
            hrr_supported_groups = True
        elif opt == '--reply-AD-size':
            reply_size = int(arg)
        elif opt == "--cookie":
            cookie = True
        elif opt == "--request":
            request = compatAscii2Bytes(arg)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if not reply_size:
        raise ValueError("--reply-AD-size not provided")

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    extensions = {ExtensionType.record_size_limit:
                  RecordSizeLimitExtension().create(2**14+1)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=extensions))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # sanity in TLS 1.3 (just check if server accepts it)
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**14+1)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity in TLS 1.3"] = conversation

    # check sizes
    for name, vers in [("TLS 1.0", (3, 1)),
                       ("TLS 1.1", (3, 2)),
                       ("TLS 1.2", (3, 3))]:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        extensions = {ExtensionType.record_size_limit:
                      RecordSizeLimitExtension().create(2**14+1)}
        node = node.add_child(ClientHelloGenerator(
            ciphers, version=vers, extensions=extensions))
        ext = {ExtensionType.record_size_limit:
               gen_srv_ext_handler_record_limit(expect_size),
               ExtensionType.renegotiation_info: None}
        node = node.add_child(ExpectServerHello(extensions=ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(request)))
        if vers == (3, 1):
            # 1/n-1 record splitting
            node = node.add_child(ExpectApplicationData(size=1))
            node = node.add_child(ExpectApplicationData(size=reply_size-1))
        else:
            node = node.add_child(ExpectApplicationData(size=reply_size))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["check server sent size in {0}".format(name)] = conversation

        # minimal size test
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        extensions = {ExtensionType.record_size_limit:
                      RecordSizeLimitExtension().create(64)}
        node = node.add_child(ClientHelloGenerator(
            ciphers, version=vers, extensions=extensions))
        ext = {ExtensionType.record_size_limit:
               gen_srv_ext_handler_record_limit(expect_size),
               ExtensionType.renegotiation_info: None}
        node = node.add_child(ExpectServerHello(extensions=ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(request)))
        remaining_size = reply_size
        if vers == (3, 1):
            # 1/n-1 record splitting
            node = node.add_child(ExpectApplicationData(size=1))
            remaining_size -= 1
        for _ in range(0, max(0, remaining_size - 64), 64):
            node = node.add_child(ExpectApplicationData(size=64))
        node = node.add_child(ExpectApplicationData(size=remaining_size % 64))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["check if server accepts minimal size in {0}".format(name)] = conversation

        # maximal size test
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        extensions = {ExtensionType.record_size_limit:
                      RecordSizeLimitExtension().create(2**16-1)}
        node = node.add_child(ClientHelloGenerator(
            ciphers, version=vers, extensions=extensions))
        ext = {ExtensionType.record_size_limit:
               gen_srv_ext_handler_record_limit(expect_size),
               ExtensionType.renegotiation_info: None}
        node = node.add_child(ExpectServerHello(extensions=ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(request)))
        if vers == (3, 1):
            # 1/n-1 record splitting
            node = node.add_child(ExpectApplicationData(size=1))
            node = node.add_child(ExpectApplicationData(size=reply_size-1))
        else:
            node = node.add_child(ExpectApplicationData(size=reply_size))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["check if server accepts maximum size in {0}".format(name)] = conversation

    for ciph, prf in [(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, "sha256"),
                      (CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, "sha384")]:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [ciph,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        extensions = {ExtensionType.record_size_limit:
                      RecordSizeLimitExtension().create(2**14+1)}
        node = node.add_child(ClientHelloGenerator(
            ciphers, version=(3, 3), extensions=extensions))
        ext = {ExtensionType.record_size_limit:
               gen_srv_ext_handler_record_limit(expect_size),
               ExtensionType.renegotiation_info: None}
        node = node.add_child(ExpectServerHello(extensions=ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(request)))
        node = node.add_child(ExpectApplicationData(size=reply_size))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["check interaction with {0} prf".format(prf)] = conversation

    # verify that the size advertised by server is the expected one
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**14+1)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData(size=reply_size)
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["check server sent size in TLS 1.3"] = conversation

    # check if server accepts small sizes
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(64)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData(size=63)
    node = node.next_sibling
    # in TLS 1.3 the content type is included in the limit so every
    # record will send one byte less than simple reading of extension would
    # indicate
    for _ in range(0, max(reply_size-63*2, 0), 63):
        node = node.add_child(ExpectApplicationData(size=63))
    node = node.add_child(ExpectApplicationData(size=reply_size%63))
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                          AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["check if server accepts minimal size in TLS 1.3"] = conversation

    # maximum size test
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**16-1)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData(size=reply_size)
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["check if server accepts maximum size in TLS 1.3"] = conversation

    # malformed extension in TLS 1.2
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    extensions = {ExtensionType.record_size_limit:
                  RecordSizeLimitExtension().create(63)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=extensions))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())
    conversations["Invalid value in extension in TLS 1.2"] = conversation

    # malformed extension in TLS 1.3
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(63)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())
    conversations["Invalid value in extension in TLS 1.3"] = conversation

    # empty extension in TLS 1.2
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    extensions = {ExtensionType.record_size_limit:
                  RecordSizeLimitExtension().create(None)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=extensions))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["empty extension in TLS 1.2"] = conversation

    # empty extension in TLS 1.3
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(None)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["empty extension in TLS 1.3"] = conversation

    # padded extension in TLS 1.2
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    extensions = {ExtensionType.record_size_limit:
                  TLSExtension(extType=ExtensionType.record_size_limit).
                  create(bytearray(b'\x00\x40\x00'))}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=extensions))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["padded extension in TLS 1.2"] = conversation

    # padded extension in TLS 1.3
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = \
        TLSExtension(extType=ExtensionType.record_size_limit).\
            create(bytearray(b'\x00\x40\x00'))
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["padded extension in TLS 1.3"] = conversation

    # too large records
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    extensions = {ExtensionType.record_size_limit:
                  RecordSizeLimitExtension().create(2**14+2)}
    node = node.add_child(ClientHelloGenerator(
        ciphers, version=(3, 3), extensions=extensions))
    ext = {ExtensionType.record_size_limit:
           gen_srv_ext_handler_record_limit(expect_size),
           ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(SetMaxRecordSize(expect_size+1))
    data = bytearray(b"GET / HTTP/1.0\r\nX-bad: ") + \
           bytearray(b"A" * (expect_size + 1 - 27)) + \
           bytearray(b"\r\n\r\n")
    assert len(data) == expect_size+1
    node = node.add_child(ApplicationDataGenerator(data))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.record_overflow))
    node.add_child(ExpectClose())
    conversations["too large record in TLS 1.2"] = conversation

    # too big records in TLSv1.3
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**14+2)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    # while the server will advertise expect_size+1, it does include
    # content type, which is added transparently to application data
    node = node.add_child(SetMaxRecordSize(expect_size+1))
    data = bytearray(b"GET / HTTP/1.0\r\nX-bad: ") + \
           bytearray(b"A" * (expect_size + 1 - 27)) + \
           bytearray(b"\r\n\r\n")
    assert len(data) == expect_size+1
    node = node.add_child(ApplicationDataGenerator(data))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.record_overflow)
    node.next_sibling.add_child(ExpectClose())
    conversations["too large record payload in TLS 1.3"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**14+2)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    # while the server will advertise expect_size+1, it does include
    # content type, which is added transparently to application data
    node = node.add_child(SetMaxRecordSize(expect_size+1))
    data = bytearray(request)
    padding_size = expect_size - len(data) + 1
    node = node.add_child(SetPaddingCallback(
        SetPaddingCallback.add_fixed_padding_cb(padding_size)))
    node = node.add_child(ApplicationDataGenerator(data))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.record_overflow)
    node.next_sibling.add_child(ExpectClose())
    conversations["too large record payload in TLS 1.3"] = conversation

    # renegotiation with changed value
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           RecordSizeLimitExtension().create(2**14+1)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           gen_srv_ext_handler_record_limit(expect_size)}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           RecordSizeLimitExtension().create(64)}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           gen_srv_ext_handler_record_limit(expect_size)}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    for _ in range(0, max(0, reply_size - 64), 64):
        node = node.add_child(ExpectApplicationData(size=64))
    node = node.add_child(ExpectApplicationData(size=reply_size % 64))
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["renegotiation with changed limit"] = conversation

    # renegotiation with dropped extension
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           RecordSizeLimitExtension().create(64)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           gen_srv_ext_handler_record_limit(expect_size)}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    node = node.add_child(ExpectApplicationData(size=reply_size))
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["renegotiation with dropped extension"] = conversation

    # resumption in TLS 1.2
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           RecordSizeLimitExtension().create(2**14)}
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           gen_srv_ext_handler_record_limit(expect_size)}
    node = node.add_child(ExpectServerHello(
        cipher=CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions={ExtensionType.renegotiation_info: None,
                    ExtensionType.record_size_limit:
                    RecordSizeLimitExtension().create(64)}))
    node = node.add_child(ExpectServerHello(
        extensions={ExtensionType.renegotiation_info: None,
                    ExtensionType.record_size_limit:
                    gen_srv_ext_handler_record_limit(expect_size)},
        resume=True))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    for _ in range(0, max(0, reply_size - 64), 64):
        node = node.add_child(ExpectApplicationData(size=64))
    node = node.add_child(ExpectApplicationData(size=reply_size % 64))
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["change size in TLS 1.2 resumption"] = conversation

    # drop in resumption in TLS 1.2
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           RecordSizeLimitExtension().create(64)}
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.record_size_limit:
           gen_srv_ext_handler_record_limit(expect_size)}
    node = node.add_child(ExpectServerHello(
        cipher=CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions={ExtensionType.renegotiation_info: None}))
    node = node.add_child(ExpectServerHello(
        extensions={ExtensionType.renegotiation_info: None},
        resume=True))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    node = node.add_child(ExpectApplicationData(size=reply_size))
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["drop extension in TLS 1.2 resumption"] = conversation

    # changing size in TLS 1.3 resumption
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**14)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ee_ext = {}
    ee_ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ee_ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ee_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    # ensure that the server sends at least one NST always
    node = node.add_child(ExpectNewSessionTicket())

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    # server can close connection without sending alert
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(close)
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))

    # start the second handshake
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    ext = OrderedDict(ext)
    ext[ExtensionType.pre_shared_key] = psk_session_ext_gen()
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(64)
    mods = []
    mods.append(psk_ext_updater())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext,
                                               modifiers=mods))
    ext = {}
    ext[ExtensionType.supported_versions] = srv_ext_handler_supp_vers
    ext[ExtensionType.pre_shared_key] = gen_srv_ext_handler_psk()
    ext[ExtensionType.key_share] = srv_ext_handler_key_share
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    # ensure that the server sends at least one NST always
    node = node.add_child(ExpectNewSessionTicket())

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData(size=63)
    node = node.next_sibling
    for _ in range(0, max(reply_size-63*2, 0), 63):
        node = node.add_child(ExpectApplicationData(size=63))
    node = node.add_child(ExpectApplicationData(size=reply_size%63))
    node = node.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())
    conversations["change size in TLS 1.3 session resumption"] = conversation

    # drop it in TLS 1.3 resumption
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(64)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ee_ext = {}
    ee_ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ee_ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ee_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    # ensure that the server sends at least one NST always
    node = node.add_child(ExpectNewSessionTicket())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.warning,
                                    AlertDescription.close_notify)
    node = node.next_sibling
    # server can close connection without sending alert
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(close)
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))

    # start the second handshake
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    ext = OrderedDict(ext)
    ext[ExtensionType.pre_shared_key] = psk_session_ext_gen()
    del ext[ExtensionType.record_size_limit]
    mods = []
    mods.append(psk_ext_updater())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext,
                                               modifiers=mods))
    ext = {}
    ext[ExtensionType.supported_versions] = srv_ext_handler_supp_vers
    ext[ExtensionType.pre_shared_key] = gen_srv_ext_handler_psk()
    ext[ExtensionType.key_share] = srv_ext_handler_key_share
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    # ensure that the server sends at least one NST always
    node = node.add_child(ExpectNewSessionTicket())

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData(size=reply_size)
    node = node.next_sibling
    node = node.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())
    conversations["drop extension in TLS 1.3 session resumption"] = conversation

    # changed value in HRR
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
    groups = [GroupName.secp256r1]
    key_shares = []
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.record_size_limit] = \
        RecordSizeLimitExtension().create(2**14+1)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))

    ext = OrderedDict()
    if cookie:
        ext[ExtensionType.cookie] = None
    ext[ExtensionType.key_share] = None
    ext[ExtensionType.supported_versions] = None
    node = node.add_child(ExpectHelloRetryRequest(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())

    ext = OrderedDict()
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    if cookie:
        ext[ExtensionType.cookie] = ch_cookie_handler
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.record_size_limit] = \
        RecordSizeLimitExtension().create(2**14+1)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    ee_ext = {}
    ee_ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if hrr_supported_groups:
        ee_ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ee_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request)))
    # this message can be sent arbitrary number of times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["HRR sanity"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
    groups = [GroupName.secp256r1]
    key_shares = []
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.record_size_limit] = \
        RecordSizeLimitExtension().create(2**14+1)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))

    ext = OrderedDict()
    if cookie:
        ext[ExtensionType.cookie] = None
    ext[ExtensionType.key_share] = None
    ext[ExtensionType.supported_versions] = None
    node = node.add_child(ExpectHelloRetryRequest(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())

    ext = OrderedDict()
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    if cookie:
        ext[ExtensionType.cookie] = ch_cookie_handler
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.record_size_limit] = \
        RecordSizeLimitExtension().create(2**14)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())
    conversations["modified extension in 2nd CH in HRR handshake"] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throught
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          islice(filter(lambda x: x[0] != 'sanity',
                                        conversations.items()), num_limit),
                          [sanity_test])

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except Exception:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Checks for record_size_limit extension")
    print("Verify that the record_size_limit extension is correctly handled")
    print("by the server: parsing, validation and interaction with basic TLS")
    print("features")
    print("version: {0}\n".format(version))

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
