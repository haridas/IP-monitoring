'''
 Copyright (C) 2012,  Haridas N <haridas.nss@gmail.com>

       This program is free software: you can redistribute it and/or modify
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

# To change this template, choose Tools | Templates
# and open the template in the editor.

__author__ = "haridas"
__date__ = "$Jul 27, 2010 9:06:07 PM$"

try:
    import sys
    import time
    import config
except:
    print "Error in loading system modules."

try:
    import ipchecker
    from report import get_report
except:
    print "The System path is not set correctly,\
            Please check the module paths."
    print  sys.exc_info()[1]
    sys.exit(0)


class ipmonitoring:

    def __init__(self):
        self.iplist = []
        self.email_list = []
        self.dnsbl_check = 'False'
        self.senderbase_check = 'False'
        self.honeypot_check = 'False'
        #print 'test',len(sys.argv),sys.argv

    def cidr_spliting(self, ip):

        if ip == '':
            return []
        else:
            ip = ip.split('/')
            #IP Validation for both cidr and ip portion.
            if len(ip) > 2:
                sys.exit()  # To exit from the program.

            elif len(ip[0].split(".")) == 4:
                for oct in ip[0].split("."):
                    if oct == '' or int(oct) > 255 or int(oct) < 0:
                        sys.exit()
            else:
                print 'Error at cidr spliting..', "\n"
                #print ip,"\n"
                sys.exit()

            #Finding the Ip range.
            if len(ip) == 1:
                return ip

            elif ip[1] != '':   # IP with cidr processed here.
                ip[1] = int(ip[1])
                last_oct = (ip[0].split("."))[3]
                #print last_oct;
                if (ip[1] >= 24) and (ip[1] <= 32):
                    pass
                else:
                    print "This Tool only suport Masking of level upto ip/24"
                    sys.exit()
                rang = 32 - ip[1]
                rang = 2 ** rang
                #Split Ip in to list for terms.
                temp_ip = ip[0].split(".")
                if len(temp_ip) != 4:
                    print "Error in the IP..."

                # Reduce one count , one ip already with input.
                rang -= 1
                # To remove cidr field from this list.
                ip.pop()
                flag = 0

                for i in range(rang):
                    local_incr = int(temp_ip[3]) + 1
                    if local_incr > 254:
                        flag = 1
                        temp_ip[3] = str(int(last_oct) - 1)

                    if flag == 0:
                        temp_ip[3] = str(int(temp_ip[3]) + 1)
                        #---->to int ---> Increment last digit ----> string.

                        ip.append('.'.join(temp_ip))
                    else:
                        ip.append('.'.join(temp_ip))
                        temp_ip[3] = str(int(temp_ip[3]) - 1)
                        #Sorted List of Ips after processing ip/cidr input.

                ip.sort()
                return ip
                #print "The list IP's to be checked:",self.ip

    def main(self):

        '''
        Main function which interface and transfer the controls to differnt
        modules.

        Responsibilties:-
        ---------------
        1.Read configurations files from the ipmonitoring.ini.
        2.Properly arrange the inputs from configurations into the compatible
        formats.
        3.Then pass it to Ipchecker module for processing ip status.
        4.Then pass the processed ip obeject to report creation module.
        5.Then send the rerport via email.
        '''
        try:
            if len(sys.argv) > 1:
                #print "checking for command line options..."
                self.read_commandline()
            else:
                #self.read_ini_conf()
                print 'Input From configuration file'

            ip_check = ipchecker.IP(self.iplist)

        except:

            print 'Input error.'
            print sys.exc_info()[1]
            print '''
                ----Input Error----

                Check your input.

                Use this format :

                ipmonitoring -[d|h|s|all] [ip,ip/cidr,...] [email,emails...]

            '''
            sys.exit()

        #    print "INput Error ..Captured from try-except block"
        #   sys.exit(0)

        status_flag = 0
        if self.dnsbl_check == 'True':
            print 'Check dnsbls'
            ip_check.check_dnsbl()
            status_flag = status_flag + 1

        if self.senderbase_check == 'True':
            print 'Sender base Check...'
            ip_check.check_senderbase()
            status_flag = status_flag + 1

        if self.honeypot_check == 'True':
            print 'honey_checking..'
            ip_check.check_honeypot()
            status_flag = status_flag + 1

        if status_flag > 0:

            try:

                report = get_report(ip_check)
                report.create_html_report()
                #Use render() function to get the string output,
                #required to wirte to report html.

                html_report = report.html_report.render()
            except:
                print 'Testing...'
                print sys.exc_info()

            #====Code for sending mails after getting all the reports.====#

            #Get the Local time in the Formated way.
            localtime = localtime = time.localtime(time.time())
            check_time = str(localtime[0]) + '-' + str(localtime[1]) + '-'\
                    + str(localtime[2])
            mail_subject = 'Ip Status Report from Sparksupport[' + \
                    check_time + ']'
            try:
                    mail = Smtp('localhost', '', '')
                    # Setting the local default MTA to send mails,
                    # from current script running user.
                    mail.from_addr(config.MAIL_FROM)
                    mail.subject(mail_subject)
                    mail.connect()
                    mail.message(html_report)
                    mail.rcpt_to(self.email_list)
                    mail.send('html')
                    mail.close()
                    print 'Report sent to mail address.'
            except:
                    print 'Error while sending mails..', sys.exc_info()[1]

            #Save the Email Addres to which we send emails.
            try:

                file = open(config.LOG_FILE, "a+")
                log = ", ".join(self.email_list) + " | " + check_time +\
                        " " + str(localtime[3]) + ":" + str(localtime[4]) +\
                        ":" + str(localtime[5]) + " | " + sys.argv[2]

                file.write(log)
                file.write("\n")
                file.close()
            except:
                print sys.exc_info()
            #print html_report

        else:

            print "Nothing to do..."

    '''
    def read_ini_conf(self):

        try:
            cfg=INIConfig(open('ipmonitoring.ini'))
        except:
            print "Configuration file not found ..."
        dnsbl_check=cfg.enabled_checking.dnsbl_check
        sender_check=cfg.enabled_checking.senderbase_check
        honey_check=cfg.enabled_checking.honeypot_check

        #Get the list of ips from configuration file.
        final_iplist=[]
        ip_list=cfg.iplist.ips.split(",");
        for ip in ip_list:
            p=self.cidr_spliting(ip)
            if p != []:
                final_iplist.extend(p)

        #Get the email ids from configuration file.
        email_list=cfg.email.list.split(",")

        self.iplist = final_iplist
        self.dnsbl_check = dnsbl_check
        self.honeypot_check = honey_check
        self.senderbase_check = sender_check
        self.email_list = email_list

    '''

    def read_commandline(self):
        '''
            The command line option API here is very strict.

            eg:

            ipmonitoring -[d|h|s|all] [ip,ip/cidr,...] [email,emails...]
        '''
        iplist = sys.argv[2].split(",")

        for ip in iplist:
            p = self.cidr_spliting(ip)
            if p != []:
                self.iplist.extend(p)

        self.email_list = sys.argv[3].split(",")
        #print self.email_list

        '''
        if sys.argv[1] == '-s':
            self.senderbase_check = 'True'
        elif sys.argv[1] =='-h':
            self.honeypot_check = 'True'
        elif sys.argv[1] == '-d':
            self.dnsbl_check = 'True'
        '''

        if sys.argv[1][0] == '-':
            comd_option = sys.argv[1][1:]

            for cmd in comd_option:
                if cmd == 's':
                    self.senderbase_check = 'True'
                elif cmd == 'd':
                    self.dnsbl_check = 'True'
                elif cmd == 'h':
                    self.honeypot_check = 'True'

                #print cmd
        elif sys.argv[1] == '-all':
            self.dnsbl_check = self.honeypot_check = self.senderbase_check = \
                    'True'


if __name__ == "__main__":
    ipmonitor = ipmonitoring()
    ipmonitor.main()
