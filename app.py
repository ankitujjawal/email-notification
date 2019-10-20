#!/usr/bin/env python
import os
import sys
from datetime import date, timedelta
import imaplib
import email
import requests
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import json
import re
import hvac


sumo_url = 'https://collectors.au.sumologic.com/receiver/v1/http/ZazDQLawapVd4kb3ZXOQd2zF2RmplzXkNv5fMOhYwVvDzq1rJFhQ=='
teams_urls = {
    "security": 'https://outlook.office.com/webhook/171bb50a-a4da-43c1-9f84-e0b98bf06b02/IncomingWebhook/84f3829a6a102b86/7e0797f6-20d4-4b78-aef7-28465bea406c',
    "network": 'https://outlook.office.com/webhook/171bb50a-a4da-43c1-9f84-e0b98bf06b02/IncomingWebhook/84f3ia6a102b86/7e0797f6-20d4-4b78-aef7-28465bea406c',
}

slack_urls = {
    "security": 'https://hooks.slack.com/services/T2R4N50/BCL1146RK/nlchSqyH5tL7U',
    "network": 'https://hooks.slack.com/services/T2R4N50/BCL1146RK/nlchSqyq5YvUr5'
}

slack_channels = {
    "security": '#email-notification-security',
    "network": '#email-notification-networks'
}

teams_channels = {
    "security": 'email-notification-security'
    "network": 'email-notification-network'
}

security_tech = []
with open("./keywords/security_tech.lst") as file:
    security_tech = file.readlines()
network_tech = []
with open("./keywords/network_tech.lst") as file:
    network_tech = file.readlines()

def send_slack(team, slack_message):
    slack_data = {
        'channel': slack_channels[team],
        'username': 'email-notifications',
        'text': slack_message,
        'icon_emoji': ':ghost:'
    }
    response = requests.post(slack_urls[team], data=json.dumps(slack_data), headers={'Content-Type': 'application/json'})
    return(response)

def send_teams(team, teams_message):
    teams_data = {
        'channel': teams_channels[team],
        'username': 'email-notifications',
        'text': teams_message,
        'icon_emoji': ':ghost:'
    }
    response = requests.post(teams_urls[team], data=json.dumps(teams_data), headers={'Content-Type': 'application/json'})
    return(response)


def send_sumo(source, msg_subject, advisory, msg_raw):
    json_payload = {'source': source,
        'advisory': msg_subject,
        'product': advisory['product'],
        'publisher': advisory['publisher'],
        'os': advisory['os'],
        'impact': advisory['impact'],
        'resolution': advisory['resolution'],
        'cve': advisory['cve'],
        'reference': advisory['reference'],
        'raw': msg_raw}
    response = requests.post(sumo_url, data=json.dumps(json_payload),headers={'Content-Type': 'application/json'})
    return(response)

def send_notifications(source, msg_subject, advisory, msg_raw):
    slack_message = '*{0}*\n`Product:` {1}\n`Publisher:` {2}\n`OS:` {3}\n `Impact:` {4}\n`Resolution:` {5}\n`CVE:` {6}\n`Reference:` {7}'.format(
        msg_subject,
        advisory['product'],
        advisory['publisher'],
        advisory['os'],
        advisory['impact'],
        advisory['resolution'],
        advisory['cve'],
        advisory['reference'])
    for tech in security_tech:
        match = fuzz.partial_ratio(msg_subject, tech)
        if match > 80:
            send_slack('security', slack_message)
    for tech in network_tech:
        match = fuzz.partial_ratio(msg_subject, tech)
        if match > 80:
            send_slack('network',slack_message)

def send_notifications(source, msg_subject, advisory, msg_raw):
    teams_message = '*{0}*\n`Product:` {1}\n`Publisher:` {2}\n`OS:` {3}\n `Impact:` {4}\n`Resolution:` {5}\n`CVE:` {6}\n`Reference:` {7}'.format(
        msg_subject,
        advisory['product'],
        advisory['publisher'],
        advisory['os'],
        advisory['impact'],
        advisory['resolution'],
        advisory['cve'],
        advisory['reference'])
    for tech in security_tech:
        match = fuzz.partial_ratio(msg_subject, tech)
        if match > 80:
            send_teams('security', teams_message)
    for tech in network_tech:
        match = fuzz.partial_ratio(msg_subject, tech)
        if match > 80:
            send_teams('network',teams_message)

def get_mail():
    emails = []
    advisory = {}
    mail = imaplib.IMAP4_SSL('outlook.office365.com')
    mail.login(imap_user, imap_password)
    mail.select("INBOX")
    result, data = mail.search(None, '(UNSEEN)')
    messages = data[0].split()
    for message_uid in messages:
        try: 
            result, data = mail.fetch(message_uid,'(RFC822)')
            for response_part in data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    msg_subject = msg.get('subject').replace('\n', '').replace('\r', '')
                    print('processing - {0}'.format(msg_subject))
                    msg_raw = msg.get_payload()
                    msg_lines = msg_raw.splitlines()
                    for line in msg_lines:
                        try:
                            if re.match('^Product\S+', line) is not None:
                                advisory['product'] = line.replace(' ', '').split(':')[1]
                        except:
                            print('An error occured.')
                        try:
                            if re.match('^Publisher\S+', line) is not None:
                                advisory['publisher'] = line.replace(' ', '').split(':')[1]
                        except:
                            print('An error occured.')
                        try:
                            if re.match('^Operating\sSystem\S+', line) is not None:
                                advisory['os'] = line.replace(' ', '').split(':')[1]
                        except:
                             print('An error occured.')
                        try:
                            if re.match('^Impact/Access\S+', line) is not None:
                                advisory['impact'] = line.replace(' ', '').split(':')[1]
                        except:
                            print('An error occured.')
                        try:
                            if re.match('^Resolution\S+', line) is not None:
                                advisory['resolution'] = line.replace(' ', '').split(':')[1]
                        except:
                            print('An error occured.')
                        try:
                            if re.match('^CVE\sNames\S+', line) is not None:
                                advisory['cve'] = line.replace(' ', '').split(':')[1]
                        except:
                            print('An error occured.')
                        try:
                            if re.match('^Reference\S+', line) is not None:
                                advisory['reference'] = line.replace(' ', '').split(':')[1]
                        except:
                            print('An error occured.')
                        if 'product' not in advisory:
                            advisory['product'] = 'unknown'
                        if 'publisher' not in advisory:
                            advisory['publisher'] = 'unknown'
                        if 'os' not in advisory:
                            advisory['os'] = 'unknown'
                        if 'impact' not in advisory:
                            advisory['impact'] = 'unknown'
                        if 'resolution' not in advisory:
                            advisory['resolution'] = 'unknown'
                        if 'cve' not in advisory:
                            advisory['cve'] = 'unknown'
                        if 'reference' not in advisory:
                            advisory['reference'] = 'unknown'
                    send_sumo('sec-alerts', msg_subject, advisory, msg_raw)
                    send_notifications('sec-alerts', msg_subject, advisory, msg_raw)
        except:
            print("An error occured")

vault_client = hvac.Client(url='https://vault.ssvc.org.io:443')
if len(sys.argv) > 1:
  vault_client.token = sys.argv[1]
else:
  vault_client.auth_iam('rolename')
imap_creds = vault_client.read('app-secrets/email-notifications')
imap_user = imap_creds["data"]["user"]
imap_password = imap_creds["data"]["password"]

get_mail()
