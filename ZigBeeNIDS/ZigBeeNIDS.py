"""
name: ZigBeeNIDS.py
description: monitors ZigBee Traffic, normalize the Traffic into a ZigBeePacket Object and Check if it could be an attack. if configured in Database, an alert is triggered
author: Bernhard Bruckner - is201812
"""
import pyshark
import configparser
import logging
import DatabaseHandling as db
from NotificationHandling import NotificationHandling
from EntityClasses import ZigBeePacket
from AttackHandling import AttackHandling
from Constants import Constants

def main():

    print("Start NIDS... ")
    logging.basicConfig(filename=Constants.CONST_Logpath, format='%(asctime)s;%(levelname)s;%(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.INFO)

    #read DB and Mail Settings from config File
    config = configparser.ConfigParser()
    cntFile = config.read(Constants.CONST_ConfigPath)

    if len(cntFile) == 0:
        print("Configfile not found. Program is terminated.")
        logging.error("Configfile not found. Program is terminated.")
        return

    #establish Database Connection
    dbCon = db.DatabaseConnection(config['mysqlDB']['host'], config['mysqlDB']['db'], config['mysqlDB']['user'], config['mysqlDB']['pass'])

    # load ThreadSettings from Database - ex. shouldAlert per Thread
    threadSettingsList = dbCon.readThreadSettings()

    # load UserSettings from Database - ex. mailaddress
    userSettings = dbCon.readUserSettings()

    # create Object for SMTP Alerts
    notifyObj = NotificationHandling(config['mailSettings']['user'], config['mailSettings']['pass'], logging, userSettings[1].value)

    #dbCon.readPossibleThreadsFromDatabase()

    #dbCon.testdbcon()
    #dbCon.recreateDatabaseStructure()

    # example for reading pcap-files; display filter is only necessary if ConBee is used
    # capture = pyshark.FileCapture('/home/bernhard/pcap_files/killerbee-tests/replay_killerbee.pcap', display_filter="udp.port == 17754 && !icmp")

    #for packet in capture:


    print("Start Capturing...")
    capture = pyshark.LiveCapture(interface="lo", display_filter="udp.port == 17754 && !icmp")

    packetCount = 1
    for packet in capture.sniff_continuously():

        if(len(packet) < 3):
            #invalid packets
            continue

        zObj = ZigBeePacket(packet)
        zigBeePacket = zObj.normalizeInput()

        if zigBeePacket is not None:
            analysePacket(dbCon, zigBeePacket, notifyObj, threadSettingsList, userSettings)
            print("Analyze Packet Nr: ", packetCount)
            packetCount+=1

def analysePacket(dbCon, zigBeePacket, notifyObj, threadSettingsList, userSettings):
    """
    method that analyzes the current zigbee packet if it contains an attack pattern
    :param dbCon: connection to database
    :param zigBeePacket: current zigbee packet
    :param notifyObj: object which is used for smtp notification
    :param threadSettingsList: list of the setting for each specific attack
    :param userSettings: list of user specific settings like mailaddress and PANID
    :return: -
    """

    listThreadIDs = [0, 0, 0, 0, 0]
    zCheck = AttackHandling(zigBeePacket, dbCon)

    if zCheck.checkResetToFactory() == True:
        listThreadIDs[0] = 1
        logging.info("checkResetToFactory detectet")
    elif zCheck.checkInsecureRejoin() == True:
        listThreadIDs[1] = 1
        logging.info("InsecureRejoin detectet")
    elif zCheck.checkReplay() == True:
        listThreadIDs[2] = 1
        logging.info("Replay detectet")
    elif zCheck.checkTransportOfNetworkKey() == True:
        listThreadIDs[3] = 1
        logging.info("Transport Key detectet")
    elif zCheck.checkTouchlinkCommissioningAttack(userSettings[0].value) == True:
        listThreadIDs[4] = 1
        logging.info("TouchlinkCommissioningAttack detectet")


    # write packet into database - returns uuid
    zigBeePacket.id = dbCon.writePacketToDatabase(zigBeePacket, listThreadIDs)

    if listThreadIDs != [0, 0, 0, 0, 0]:
        thread = ''
        if listThreadIDs[0] != 0 and threadSettingsList[0].shouldAlert == 1:
            thread = threadSettingsList[0].name

        if listThreadIDs[1] != 0 and threadSettingsList[1].shouldAlert == 1:
            if len(thread) > 0:
                thread += ', '
            thread += threadSettingsList[1].name

        if listThreadIDs[2] != 0 and threadSettingsList[2].shouldAlert == 1:
            if len(thread) > 0:
                thread += ', '
            thread += threadSettingsList[2].name

        if listThreadIDs[3] != 0 and threadSettingsList[3].shouldAlert == 1:
            if len(thread) > 0:
                thread += ', '
            thread += threadSettingsList[3].name

        if listThreadIDs[4] != 0 and threadSettingsList[4].shouldAlert == 1:
            if len(thread) > 0:
                thread += ', '
            thread += threadSettingsList[4].name

        if len(thread) > 0:
            notifyObj.sendMail(thread,zigBeePacket)
        else:
            print("Notification for this Thread is disabled in Database!")
            logging.info("Notification for this Thread is disabled in Database!")

if __name__ == '__main__': main()