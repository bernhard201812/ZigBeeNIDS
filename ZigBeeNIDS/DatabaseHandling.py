"""
name: DatabaseHandling.py
description: Manages all connections to mysql Database
author: Bernhard Bruckner - is201812
"""
import mysql
from mysql.connector import Error
from EntityClasses import ThreadSettings, GeneralSettings
from Constants import Constants
import uuid
import time


class DatabaseConnection:
    def __init__(self, dbhost, dbdatabase, dbuser, dbpassword):
        self.dbhost = dbhost
        self.dbdatabase = dbdatabase
        self.dbuser = dbuser
        self.dbpassword = dbpassword
        self.connection = self.connect()

    def connect(self):
        """
        method that connects to the Database
        :return: -
        """

        try:
            connection = mysql.connector.connect(host=self.dbhost, database=self.dbdatabase, user=self.dbuser, password=self.dbpassword)

            if not connection.is_connected():
                print("Error connecting to Database! Program quits")
                quit()
            else:
                # use prepared Statement
                connection.cursor = connection.cursor(prepared=True)

        except Error as e:
            print("Error while connecting to MySQL!", e)
            print("Program stopped!")
            quit()

        return connection

    def disconnect(self):
        """
        method that closes the database connection
        :return: -
        """

        try:
            if self.connection.is_connected():
                self.connection.close()
            print("MySQL connection is closed")
        except Error as e:
            print("Error while closing MySQL Connection", e)

    def testdbcon(self):
        """
        method that tests the connection to the Database; print the Mysql Server Version and the used database
        :return: -
        """

        try:
            if self.connection is None or not self.connection.is_connected():
                self.connection = self.connect()

            if self.connection.is_connected():
                dbInfo = self.connection.get_server_info()
                print("Connected to MySQL Server version ", dbInfo)
                cursor = self.connection.cursor
                cursor.execute("select database();")
                record = cursor.fetchone()
                print("You're connected to database: ", record)

        except Error as e:
            print("Error while connecting to MySQL", e)
        finally:
            if self.connection.is_connected():
                cursor.close()
                self.disconnect()

    def writePacketToDatabase(self, zigBeePacket, listThreadIDs):
        """
        method that inserts current packet into tbZigBeeData and tbDataThreadMapping if an attack is detected
        :param zigBeePacket: current normalized zigbee packet
        :param listThreadIDs: list with detected attacks of the current packet
        :return: random uuid of current packet
        """


        try:

            if self.connection is None or not self.connection.is_connected():
                self.connection = self.connect()

            if self.connection.is_connected():
                cursor = self.connection.cursor

                trans_uuid = str(uuid.uuid4())   # Random Foreign Key between tbZigBeeData and tbDataThreadMapping

                isInsecureRejoinRequest = 0

                if zigBeePacket.cmd_id == Constants.CONST_InsecureRejoinRequest and \
                        zigBeePacket.nwk_frame_typ == Constants.CONST_InsecureRejoinFrameType and \
                        zigBeePacket.security == "0":
                    print("insecure rejoin request detected")
                    isInsecureRejoinRequest = 1

                prep_insert_statement = "INSERT INTO tbZigBeeData(uuid, sourceaddress, destaddress, frame_type, cmd_id, security, zbee_sec_mic, zbee_sec_counter, nwk_seqno , isInsecureRejoinRequest, isPossibleThread) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,0)"
                prepTuple = (trans_uuid, zigBeePacket.nwk_source, zigBeePacket.nwk_dst, zigBeePacket.nwk_frame_typ,
                             zigBeePacket.cmd_id, zigBeePacket.security, zigBeePacket.zbee_sec_mic,
                             zigBeePacket.zbee_sec_counter, zigBeePacket.nwk_seqno, isInsecureRejoinRequest)
                cursor.execute(prep_insert_statement, prepTuple)

                # insert detected attacks into tbDataThreadMapping
                if listThreadIDs[0] == 1:
                    #ResetToFactory detected
                    prep_ins_factoryReset = "INSERT INTO tbDataThreadMapping(tbZigBeeDataUUID, tbThreadSettingsID) VALUES (%s,%s)"
                    prepFR = (trans_uuid, 1)
                    cursor.execute(prep_ins_factoryReset, prepFR)

                if listThreadIDs[1] == 1:
                    #InsecureRejoin detected
                    prep_ins_insecRejoin = "INSERT INTO tbDataThreadMapping(tbZigBeeDataUUID, tbThreadSettingsID) VALUES (%s,%s)"
                    prepIR = (trans_uuid, 2)
                    cursor.execute(prep_ins_insecRejoin, prepIR)

                if listThreadIDs[2] == 1:
                    # Replay detected
                    prep_ins_replay = "INSERT INTO tbDataThreadMapping(tbZigBeeDataUUID, tbThreadSettingsID) VALUES (%s,%s)"
                    prepReplay = (trans_uuid, 3)
                    cursor.execute(prep_ins_replay, prepReplay)

                if listThreadIDs[3] == 1:
                    # Transport Key detected
                    prep_ins_transportkey = "INSERT INTO tbDataThreadMapping(tbZigBeeDataUUID, tbThreadSettingsID) VALUES (%s,%s)"
                    prepTK = (trans_uuid, 4)
                    cursor.execute(prep_ins_transportkey, prepTK)

                if listThreadIDs[4] == 1:
                    # TouchlinkCommissioningAttack detected
                    prep_ins_touchlink= "INSERT INTO tbDataThreadMapping(tbZigBeeDataUUID, tbThreadSettingsID) VALUES (%s,%s)"
                    prepTouchlink= (trans_uuid, 5)
                    cursor.execute(prep_ins_touchlink, prepTouchlink)

                # if an attack occured
                if listThreadIDs != [0, 0, 0, 0, 0]:
                    print("attack occured")
                    prep_update = "UPDATE tbZigBeeData set isPossibleThread = 1 WHERE uuid = %s"
                    cursor.execute(prep_update, (trans_uuid,))

            self.connection.commit()

            return trans_uuid

        except Error as e:
            print("Error while writing to MySQL", e)
            self.disconnect()
            return -1

    def checkDBifReplay(self, zigBeePacket):
        """
        method that check the current packet against Replay
        :param zigBeePacket: current zigbeepacket
        :return: True if an Replay was detected
        """

        try:
            #check for empty packets
            if len(zigBeePacket.nwk_dst) == 0 and len(zigBeePacket.zbee_sec_counter) == 0:
                return False

            if not self.connection.is_connected():
                self.connection = self.connect()

            if self.connection.is_connected():
                cursor = self.connection.cursor

                sql_select_possible_replay = """SELECT ID FROM tbZigBeeData where destaddress = %s AND zbee_sec_mic = %s AND zbee_sec_counter = %s AND nwk_seqno= %s;"""
                prepReplay = (zigBeePacket.nwk_dst, zigBeePacket.zbee_sec_mic, zigBeePacket.zbee_sec_counter, zigBeePacket.nwk_seqno)
                cursor.execute(sql_select_possible_replay, prepReplay)
                allResults = cursor.fetchall()

                if len(allResults) > 0:
                    return True
                else:
                    return False
        except Error as e:
            print("Error reading from MySQL", e)
            return False

    def checkDBifInsecureRejoin(self, zigBeePacket):
        """
        method that check if current packet is an Insecure Rejoin Response and search in database for the Request
        :param zigBeePacket: current zigbee packet
        :return: True if an Insecure Rejoin was detected
        """


        try:
            if not self.connection.is_connected():
                self.connection = self.connect()

            if self.connection.is_connected():
                cursor = self.connection.cursor

                sql_select_possible_insecureRejoin = "SELECT * FROM tbZigBeeData where sourceaddress = %s and isInsecureRejoinRequest = 1"
                val = (zigBeePacket.cmd_addr,)
                cursor.execute(sql_select_possible_insecureRejoin, val)

                allResults = cursor.fetchall()

                if len(allResults) > 0:
                    return True
                else:
                    return False
        except Error as e:
            print("Error reading from MySQL", e)
            return False

    def readThreadSettings(self):
        """
        method that reads the Settings of the attacks
        :return: A List of attacks and their configuration
        """

        try:
            if not self.connection.is_connected():
                self.connection = self.connect()

            if self.connection.is_connected():
                cursor = self.connection.cursor
                cursor.execute("select id, name, shouldAlert from tbThreadSettings")
                records = cursor.fetchall()

                threadList = []

                for row in records:
                    threadList.append(ThreadSettings(row[0], row[1], row[2]))

                return threadList
        except Error as e:
            print("Error reading from MySQL", e)
            return []

    def readUserSettings(self):
        """
        method that reads the user specific settings
        :return: A List of user secific setttings like PANID and Mailaddress
        """

        try:

            if not self.connection.is_connected():
                self.connection = self.connect()

            if self.connection.is_connected():
                cursor = self.connection.cursor
                cursor.execute("select id, name, value from tbGeneralSettings")
                records = cursor.fetchall()

                settingsList = []

                for row in records:
                    settingsList.append(GeneralSettings(row[0],row[1],row[2]))

                return settingsList
        except Error as e:
            print("Error reading from MySQL", e)
            return []

    def readPossibleThreadsFromDatabase(self):
        """
        method that prints all detected attacks inclusive their details
        :return: -
        """
        try:
            print(self.connection.is_connected())
            if not self.connection.is_connected():
                self.connection = self.connect()

            if self.connection.is_connected():
                cursor = self.connection.cursor
                sql_select_possible_threads ="""SELECT tbZigBeeData.uuid as ZigBeePacketID, sourceaddress, destaddress, creationTime, 
                                                tbThreadSettings.name as ThreadName, tbThreadSettings.shouldAlert as AlertEnabled
                                                FROM tbZigBeeData
                                                LEFT JOIN tbDataThreadMapping ON tbZigBeeData.uuid = tbDataThreadMapping.tbZigBeeDataUUID
                                                LEFT JOIN tbThreadSettings ON tbDataThreadMapping.tbThreadSettingsID = tbThreadSettings.ID
                                                where isPossibleThread = 1;"""

                cursor.execute(sql_select_possible_threads)
                records = cursor.fetchall()
                print("Total number of possible Threads: ", cursor.rowcount)

                for row in records:
                    print("UUID:", row[0], )
                    print("Source: ", row[1])
                    print("Dest: ", row[2])
                    print("Timestamp: ", row[3])
                    print("ThreadName: ", row[4])
                    print("ShouldAlert: ", row[5], "\n")
        except Error as e:
            print("Error reading from MySQL", e)

    def recreateDatabaseStructure(self):
        """
        method which recreates the whole database structure
        :return: -
        """

        sql_drop_table_ZigBeeData  ="DROP TABLE IF EXISTS tbZigBeeData;"
        sql_drop_table_ThreadMapping  ="DROP TABLE IF EXISTS tbDataThreadMapping;"
        sql_drop_table_GeneralSettings  ="DROP TABLE IF EXISTS tbGeneralSettings;"
        sql_drop_table_ThreadSettings ="DROP TABLE IF EXISTS tbThreadSettings;"

        sql_create_table_ZigBeeData = """CREATE TABLE IF NOT EXISTS tbZigBeeData(id INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
                                              uuid VARCHAR(50) NOT NULL,
                                              sourceaddress VARCHAR(50),
                                              destaddress VARCHAR(50),
                                              frame_type VARCHAR(10),                                            
                                              cmd_id VARCHAR(10),
                                              security VARCHAR(1),
                                              zbee_sec_mic VARCHAR(20),
                                              zbee_sec_counter VARCHAR(20),
                                              nwk_seqno VARCHAR(20),
                                              isPossibleThread INTEGER,
                                              isInsecureRejoinRequest INTEGER,
                                              creationTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP());"""
        sql_create_table_DataThreadMapping = """CREATE TABLE IF NOT EXISTS tbDataThreadMapping(id INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
                               tbZigBeeDataUUID VARCHAR(50) NOT NULL,
                               tbThreadSettingsID INTEGER NOT NULL);"""
        sql_create_table_GeneralSettings = """CREATE TABLE IF NOT EXISTS tbGeneralSettings(id INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
                                      name VARCHAR(100),
                                      value VARCHAR(100));"""
        sql_create_table_ThreadSettings = """CREATE TABLE IF NOT EXISTS tbThreadSettings(id INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,
                                    name VARCHAR(100),
                                    shouldAlert INTEGER NOT NULL);"""

        sql_ins_tbThreadSettings = "INSERT INTO tbThreadSettings(name, shouldAlert) VALUES('ResetToFactory', 1)"
        sql_ins_tbThreadSettings1 = "INSERT INTO tbThreadSettings(name, shouldAlert) VALUES('InsecureRejoin', 1)"
        sql_ins_tbThreadSettings2 = "INSERT INTO tbThreadSettings(name, shouldAlert) VALUES('Replay', 0)"
        sql_ins_tbThreadSettings3 = "INSERT INTO tbThreadSettings(name, shouldAlert) VALUES('TransportKeyCommand', 1)"
        sql_ins_tbThreadSettings4 = "INSERT INTO tbThreadSettings(name, shouldAlert) VALUES('TouchlinkCommissioningAttack', 1)"

        sql_ins_tbGeneralSettings = "INSERT INTO tbGeneralSettings(name, value) VALUES('PANID', '')"
        sql_ins_tbGeneralSettings1 = "INSERT INTO tbGeneralSettings(name, value) VALUES('Mailaddress', 'is201812@fhstp.ac.at')"

        try:
            if self.connection.is_connected():
                cursor = self.connection.cursor

                #drop tables if exists
                cursor.execute(sql_drop_table_ZigBeeData)
                cursor.execute(sql_drop_table_ThreadMapping)
                cursor.execute(sql_drop_table_GeneralSettings)
                cursor.execute(sql_drop_table_ThreadSettings)

                #create tables
                cursor.execute(sql_create_table_ZigBeeData)
                cursor.execute(sql_create_table_DataThreadMapping)
                cursor.execute(sql_create_table_GeneralSettings)
                cursor.execute(sql_create_table_ThreadSettings)

                # insert default values for settings
                cursor.execute(sql_ins_tbThreadSettings)
                cursor.execute(sql_ins_tbThreadSettings1)
                cursor.execute(sql_ins_tbThreadSettings2)
                cursor.execute(sql_ins_tbThreadSettings3)
                cursor.execute(sql_ins_tbThreadSettings4)
                cursor.execute(sql_ins_tbGeneralSettings)
                cursor.execute(sql_ins_tbGeneralSettings1)

                self.connection.commit()

        except Error as e:
            print("Error creating Database Structure in MYSQL!", e)