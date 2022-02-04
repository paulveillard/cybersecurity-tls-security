#!/usr/bin/python3

import ssl, socket
import sys
import time, datetime
import yaml
import smtplib

exitcode = 0
messages = []

'''
Read yaml file and return dictionary
'''
def parse_yaml(filepath):
    with open(filepath) as f:
        dataMap = yaml.safe_load(f)
    return dataMap


def getCertExpiry(domain):
    try:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        s.connect((domain, 443))
        cert = s.getpeercert()
        return int(time.mktime(datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").timetuple()))
    except:
        return 0

def check_domain_group(domains,notify_before):
    messages = []
    for domain in domains:
        expiry_date = getCertExpiry(domain)
        current_timestamp = int(time.time())
        days_till_expiry = (expiry_date - current_timestamp)//(60*60*24)
        if days_till_expiry <= notify_before:
            messages.append("Certificate for "+domain+" will expire in "+str(days_till_expiry)+" days")
    return messages

def send_mail(mail_meta,message):
    sender = mail_meta['sender']
    receivers = mail_meta['receivers']
    subject = mail_meta['subject']
    body = """\
From: %s
To: %s
Subject: %s

%s
""" % (sender,', '.join(receivers),subject,'\n'.join(message))
    try:
        if 'server' in mail_meta and 'username' in mail_meta and 'password' in mail_meta:
            server = mail_meta['server']
            username = mail_meta['username']
            password = mail_meta['password']
            mail_client = smtplib.SMTP_SSL(server)
            mail_client.login(username,password)
            mail_client.sendmail(sender, receivers, body)
            print("Successfully sent email")
    except:
       print("Error: unable to send email:",sys.exc_info()[0])

def handle_notification(notification_group,message):
    if notification_group['type'] == 'mail':
        send_mail(notification_group['mail_meta'],message)

def main(argv):
    yaml_dic = parse_yaml(argv[0])
    for key, domain_group in yaml_dic['domain_groups'].items():
        messages =check_domain_group(domain_group['domains'],domain_group['notify_before'])
        if len(messages) and 'notification_groups' in domain_group:
            for notification_group in domain_group['notification_groups']:
                handle_notification(yaml_dic['notification_groups'][notification_group],messages)

if __name__ == "__main__":
   main(sys.argv[1:])

