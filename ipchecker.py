#!/usr/bin/python
'''
 This file is part of IPmonitoring Tool

 Copyright (C) 2012,  Haridas N <haridas.nss@gmail.com>

       IPmonitoring is free software: you can redistribute it and/or modify
       it under the terms of the GNU General Public License as published by
       the Free Software Foundation, either version 3 of the License, or
        any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>

'''

__author__ = 'Haridas N'
__date__ = '2010-07-13 12:13:00'

import urllib
import re
import commands


class IP:
    '''

    Ip Checker
    ----------

        Class IP with one public data member one list of ips and set
        of methods to perform specific operations.

        Developed using OOPs method. So here we have the followoing main
        classes and its datas, and methods to work over these data.

        Class Name: IP

    Datas:-

            Initialize the Ip list under the __init__ function and also
            have facility to receive CIDR formated imputs.

               Methods:

                1. Get senderbasescore()

                    Check the senderbase scroe of each ips in the object ip
                    list. if it have more than one ip then
                    it will check it for each ip.

                2. Get mxtoolbox status()

                    Similar to the above method here it will retrive the
                    status of the blacklisting and the DNSBL
                    for each IP in the IP list.

            3. Get honeypot status of the ip

                    Get number of honepot hits for these ips

          '''

    def __init__(self, ip):

        assert isinstance(ip, list), "Provide List of Ip's"
        self.ip = ip

    def __del__(self):
            pass

    def getip(self):
        print ("This is the Ip: {0}".format(self.ip))

    def check_senderbase(self):
        #print "Checking sender base..."
                # Create a dictionry to save Sender base check. key
                   # IP ---> value: status.

        self.senderbase_status = {}

        # Select each ip from IP list and get the corresponding page
        # from senderbase.org and then crawel the required area.

        for ip in self.ip:

            url = 'http://www.senderbase.org/senderbase_queries' +\
                    '/detailip?search_string=' + ip

            #import pdb; pdb.set_trace()

            sock = urllib.urlopen(url)
            htmlfile = sock.read()
            sock.close()

            # Pattern used to get the reputation status form the Senderbase
            # webpage.Need some changes here when they changes Codes.
            regex_pattern = re.compile("""SenderBase reputation score""" + \
                                       """</td>.*?<td[a-zA-Z="%0-9' ]*>""" + \
                                       """.*?([a-zA-Z]+).*?</td>""",
                                       re.I | re.S | re.M)

            final_result = regex_pattern.findall(htmlfile)
            #print ip,":", final_result[0];

            #Save the result in to a list.
            try:
                self.senderbase_status[ip] = final_result[0]
            except IndexError:
                pass

            '''
            keys=self.senderbase_status.keys()
            keys.sort()   #inplace replacement of sorted keys.
            for ip in keys:
                print ip,":",self.senderbase_status[ip];

                SenderBase reputation score</td>
                <td width="20%" class="good">
                Good
                </td>

                    Regex more:

                    re.I --> To get Case Insensitive Matching.
                    re.S --> To Match all characters with "." including newline
                    re.M --> To match Multiple line.

                    #End of Sender base function.

            '''

    def check_dnsbl(self):
        '''
        Check_dnsbl(): Check ips with DNS Black lists. and gives the
        Result of blacklisted DNSBL's.
        '''

        dnsbls = ['pam.mrs.kithrup.com', 'access.redhawk.org',
                  'all.spamblock.unit.liu.se', 'assholes.madscience.nl',
                  'blackholes.five-ten-sg.com', 'blackholes.intersil.net',
                  'blackholes.mail-abuse.org', 'blackholes.sandes.dk',
                  'blackholes.wirehub.net', 'blacklist.sci.kun.nl',
                  'bl.borderworlds.dk', 'bl.csma.biz', 'block.dnsbl.sorbs.net',
                  'blocked.hilli.dk', 'blocklist2.squawk.com',
                  'blocklist.squawk.com', 'bl.redhatgate.com',
                  'bl.spamcannibal.org', 'bl.spamcop.net', 'bl.starloop.com',
                  'bl.technovision.dk', 'cart00ney.surriel.com',
                  'cbl.abuseat.org', 'dev.null.dk', 'dews.qmail.org',
                  'dialup.blacklist.jippg.org', 'dialup.rbl.kropka.net',
                  'dialups.mail-abuse.org', 'dialups.visi.com',
                  'dnsbl-1.uceprotect.net', 'dnsbl-2.uceprotect.net',
                  'dnsbl-3.uceprotect.net', 'dnsbl.antispam.or.id',
                  'dnsbl.cyberlogic.net', 'dnsbl.njabl.org',
                  'dnsbl.solid.net', 'dnsbl.sorbs.net', 'duinv.aupads.org',
                  'dul.dnsbl.sorbs.net', 'dul.ru', 'dun.dnsrbl.net',
                  'dynablock.wirehub.net', 'fl.chickenboner.biz',
                  'forbidden.icm.edu.pl', 'hil.habeas.com',
                  'http.dnsbl.sorbs.net', 'intruders.docs.uu.se',
                  'korea.services.net', 'mail-abuse.blacklist.jippg.org',
                  'map.spam-rbl.com', 'misc.dnsbl.sorbs.net',
                  'msgid.bl.gweep.ca', 'multihop.dsbl.org',
                  'no-more-funn.moensted.dk', 'orbs.dorkslayers.com',
                  'orvedb.aupads.org', 'proxy.bl.gweep.ca', 'psbl.surriel.com',
                  'pss.spambusters.org.ar', 'rblmap.tu-berlin.de',
                  'rbl.schulte.org', 'rbl.snark.net', 'rbl.triumf.ca',
                  'relays.bl.gweep.ca', 'relays.bl.kundenserver.de',
                  'relays.dorkslayers.com', 'relays.mail-abuse.org',
                  'relays.nether.net', 'rsbl.aupads.org', 'sbl.csma.biz',
                  'sbl.spamhaus.org', 'sbl-xbl.spamhaus.org',
                  'smtp.dnsbl.sorbs.net', 'socks.dnsbl.sorbs.net',
                  'spam.dnsbl.sorbs.net', 'spam.dnsrbl.net',
                  'spamguard.leadmon.net', 'spam.olsentech.net',
                  'spamsources.dnsbl.info', 'spamsources.fabel.dk',
                  'spamsources.yamta.org', 'spam.wytnij.to',
                  'unconfirmed.dsbl.org', 'vbl.messagelabs.com',
                  'web.dnsbl.sorbs.net', 'whois.rfc-ignorant.org',
                  'will-spam-for-food.eu.org', 'xbl.spamhaus.org',
                  'zombie.dnsbl.sorbs.net', 'ztl.dorkslayers.com',
                  'cbl.abuseat.org', 'bhnc.njabl.org', 't1.dnsbl.net.au',
                  'list.dsbl.org', 'luckyseven.dnsbl.net',
                  'blacklist.spambag.org', 'dyna.spamrats.com',
                  'spam.spamrats.com', 'ubl.unsubscore.com', 'db.wpbl.info',
                  '0spam.fusionzero.com']

        #dnsbls=['dead_list checker.']
        #Create a dictnory for store the

        self.dnsbl_status = {}

        for ip in self.ip:

            #Reverse IP address to use for DNSBL query.
            self.dnsbl_status[ip] = ['']
            local_list = []

            ip_split = ip.split(".")
            ip_split.reverse()
            ip_reverse = ".".join(ip_split)

            for rbl in dnsbls:
                dig_output = commands.getoutput("dig "
                                                + ip_reverse + "."
                                                + rbl)

                regex_pattern = re.compile("127.0.0.([2-9]|10)")
                dig_result = regex_pattern.findall(dig_output)

                # Check for the regex has any result.
                if len(dig_result) >= 1:
                    local_list.append(rbl)

            # Store the rbl list in to the dictnory.
            self.dnsbl_status[ip] = local_list
            #print ip,':',local_list  #output the blacklist infor of each ip.

    def check_honeypot(self):
        '''

        check_honeypot() function takes the ip list from the object variable
        and then it will search for the projecthonypot.ort site for
        the ip status.

        input : list of ips from object variable self.ip
        output: prints the result of each ip and provide an object dictnory
                self.honeypot_result;

        '''

        #http://projecthoneypot.org/ip_208.101.1.74
        # Dict to save result of all ips. which is an nested one,
        # ie; each value field holds another dictnory value.
        self.honeypot_result = {}

        for ip in self.ip:
            # Dict to save result of an ip. which includes
            # three keys and values each.
            ip_result = {}
            url = 'http://projecthoneypot.org/ip_' + ip
            sock = urllib.urlopen(url)

            htmlfile = sock.read()
            sock.close()

            regex_pattern0 = re.compile('''We don\'t have data on\
                                        this IP currently''', re.I)

            empty_check = regex_pattern0.findall(htmlfile)

            if len(empty_check) == 0:

                #print htmlfile;
                #Regular expression to scrawl elements from the honeypot page.
                regexp_pattern1 = re.compile(
                    '''First&nbsp;Received&nbsp;From</td>.*?<td[a-zA-Z0-9=":;\
                ]+>.*?\s*([a-z0-9, ]+)''', re.I | re.S | re.M)
                regexp_pattern2 = re.compile(
                    '''Last&nbsp;Received&nbsp;From</td>.*?<td[a-zA-Z0-9=":;\
                ]+>.*?\s*([a-z0-9, ]+)''', re.I | re.S | re.M)

                regexp_pattern3 = re.compile(
                    '''Number&nbsp;Received</td>.*?<td[a-zA-Z0-9=":;\
                ]+>.*?\s*([a-z0-9, ]+)''', re.I | re.S | re.M)

                first_received = regexp_pattern1.findall(htmlfile)
                last_received = regexp_pattern2.findall(htmlfile)
                total_number = regexp_pattern3.findall(htmlfile)

                #print first_received,last_received,total_number

                if first_received and last_received and total_number:
                    ip_result = {'First Received From': first_received[0],
                                 'Last Received From': last_received[0],
                                 'Total number of mails': total_number[0]}

                    #print '\n\t\t=======',ip,'=======\n\n
                    #<First Received From>     :',first_received[0],'\n\n
                    #<Last Received From>      :',last_received[0],'\n\n
                    #<Total number of mails >  :',total_number[0],'\n\n'
                    self.honeypot_result[ip] = ip_result
                else:
                    #print "Please Check ...Crawler
                    #couldn't yeild any result..."
                    break
            else:
                print("{0}: Not listed".format(ip))
                self.honeypot_result[ip] = {}

if __name__ == '__main__':
    print'Main program'
