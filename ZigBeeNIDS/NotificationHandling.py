"""
name: NotificationHandling.py
description: class which is used for sending Notifications via SMTP if an attack occured, use local postfix and gmail as Relayhost
author: Bernhard Bruckner - is201812
"""
import logging
import smtplib
from email.mime.text import MIMEText

class NotificationHandling:
    def __init__(self, user, password, logging, mailaddress):
        self.user = user
        self.password = password
        self.logging = logging
        self.mailaddress = mailaddress

    def sendMail(self, thread, zigbeepacket):

        sent_from = self.user
        sent_to = self.mailaddress

        msg = """Hi,
a possible Attack has been detected!

Thread: %s
ZigBeePacketID: %s
Source Address: %s
Destination Address: %s
Source PAN: %s
Destination PAN: %s
Time: %s

Best Regards from your NIDS""" % (thread, zigbeepacket.id, str(zigbeepacket.nwk_source), str(zigbeepacket.nwk_dst), str(zigbeepacket.pan_source), str(zigbeepacket.pan_dst), zigbeepacket.creationDate.strftime("%d.%m.%Y %H:%M:%S"))

        msg = MIMEText(msg, 'plain')
        msg['Subject'] = 'A possible attack has been detected'
        msg['To'] = sent_to
        msg['From'] = 'ZigBee NIDS'

        try:

            smtp_server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            smtp_server.ehlo()
            smtp_server.login(self.user, self.password)
            smtp_server.sendmail(sent_from, sent_to, msg.as_string())
            smtp_server.close()
            print ("Notification Email sent successfully!")
            self.logging.info("Notification Email sent successfully!")
        except Exception as ex:
            print ("Error Sending Notification E-Mail",ex)
            self.logging.error("Error Sending Notification E-Mail",ex)