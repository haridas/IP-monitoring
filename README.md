Ipmonitoring
============

Check the reputation of your IP before seinding mails from it. If it doesn't
have good reputation then the chance for your mails go into users' spam folder
is very high.


If the IP hasn't have good reputation, most probabley it was due to your
incorrect settings on the DNS zone file. So you need to correctly set the
following settings to claim that you are the soul owner of mails that you are
being sending from this IP and domain.


1. SPF settings

    This is a simple TXT record in the zone file to map your domain name to the
    IP from which you are sending mails. So the ISPs can recheck the origin of
    the mail.

2. DKIM settings

    This is kinda header encryption to your mail headers so that the ISP's can
    make sure that nobody in the midle manipulated the mail headers and
    contents.

    For the DKIM setup, you have to do little more work. First you have to sign
    all your mail using a private key before seinding it out. And then you have
    to keep the public key on DNS zone record as TXT format, so the ISP's can
    fetch this public key and make sure that your nobody in the middle tempered
    your mail. 

    This is kinda more secure method. Most of the ISPs fine with the SPF
    setttings only. So first do the SPF and then setup the DKIM.
    
