Ipmonitoring
============

**WARNING**: The main components of this project relay up on extracting contents 
from the target web sites. There is a chance in
future those sites may change their layout. So in that case this program 
has to adopt those changes on the web page to work properly.

This program basically checks the reputation of given list of IPs against set
of predefined DNSBLs, from Project honeypot site, and from Senderbase site. The
functionality of Project honeypot and senderbase checks are relay up on their
site structure. So please don't expect this works if they changed the sites'
layout. Please contact me if you need any help on that.

Check the reputation of your IP before sending mails from it. If it doesn't
have good reputation then the chance for your mails go into users' spam folder
is very high.


If the IP hasn't have good reputation, most probably it was due to your
incorrect settings on the DNS zone file. So you need to correctly set the
following settings to claim that you are the soul owner of mails that you are
being sending from this IP and domain.


1. SPF settings

    This is a simple TXT record in the zone file to map your domain name to the
    IP from which you are sending mails. So the ISPs can recheck the origin of
    the mail. Microsoft use their on proprietary version if SPF, it's named as
    Sender ID.

2. DKIM settings

    This is kinda header encryption to your mail headers so that the ISP's can
    make sure that nobody in the midle manipulated the mail headers and
    contents.

    For the DKIM setup, you have to do little more work. First you have to sign
    all your mail using a private key before seinding it out. And then you have
    to keep the public key on DNS zone record as TXT format, so the ISP's can
    fetch this public key and make sure that nobody in the middle tempered
    your mail. 

    This is kinda more secure method. Most of the ISPs fine with the SPF
    setttings only. So first do the SPF and then setup the DKIM.

HOW To Run It
============

1. Clone the repository into your local machine.
2. Go into the main project folder, and type -
    $ python ipmonitoring.py --help # To see the help

                USAGE FORMAT:

            python ipmonitoring.py -[d|h|s|all] [ip,ip/cidr,...] 

    where:

    Option -d for DNSBL check
    Option -h for honeypot check
    Option -s for senderbase check
    Option -all for check all the option

    ip/cidr - Input single IP or multiple range of IP in CIDR format.


