#!/usr/bin/env python

import socket, sys
from OpenSSL import SSL

cafile, host = sys.argv[1:]

def printcert(x509):
    """Display an X.509 certificate"""
    fields = {'country_name': 'Country',
        'SP': 'State/Province',
        'L': 'Locality',
        'O': 'Organization',
        'OU': 'Organizational Unit',
        'CN': 'Common Name',
        'email': 'E-Mail'}

    for field, desc in fields.items():
        try:
            print "%30s: %s" % (desc, getattr(x509, field))
        except:
            pass

cnverified = 0

def verify(connection, certificate, errnum, depth,  ok):
    global cnverifie

    subject = certificate.get_subject()
    issuer = certificate.get_issuer()

    print " This Certificate is from:"
    printcert(subject)

    print "\nIssuer's Details:"
    printcert(issuer)

    if not ok:
        print "--" * 50
        print "* \t\t\t\t Could not verify certificate.  \t\t\t\t  *"
        print "--" * 50
        return 0

    print "--" * 50
    return 1 
    
ctx = SSL.Context(SSL.SSLv23_METHOD)
ctx.load_verify_locations(cafile)

ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify)

print "--" * 50
print "\t\t\t\tSocket Creation using Open SSL :",
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "OK"
print "--" * 50

ssl = SSL.Connection(ctx, s)

print "--" * 50
print "\t\t\t\tEstablishing SSL Connection :",
ssl.connect((host, 443))
print "OK"
print "--" * 50


print "\t\t\t\tGet method HTTP Request:"
print "--" * 50
ssl.sendall("GET / HTTP/1.0\r\n\r\n")
print "OK"
print "--" * 50

while 1:
    try:
        buf = ssl.recv(4096)
    except SSL.ZeroReturnError:
        break
    sys.stdout.write(buf)

ssl.close()
