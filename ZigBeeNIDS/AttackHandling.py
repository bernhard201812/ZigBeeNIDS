"""
name: AttackHandling.py
description: check the current packet against defined attack vectors
author: Bernhard Bruckner - is201812
"""

from Constants import Constants


class AttackHandling:
    def __init__(self, zigbeepacket, dbCon):
        self.zigbeepacket = zigbeepacket
        self.dbCon = dbCon

    def checkReplay(self):
        return self.dbCon.checkDBifReplay(self.zigbeepacket)

    def checkResetToFactory(self):
        if self.zigbeepacket.zcl_command_id == Constants.CONST_FactoryReset:
            print("Reset To Factory detected")
            return True

    def checkTransportOfNetworkKey(self):
        # check if Transport Key Command and key_type is Network Key
        if self.zigbeepacket.zbee_aps_cmd_id == Constants.CONST_TransportKeyCommand and \
                self.zigbeepacket.zbee_aps_cmd_key_type == Constants.CONST_TransportKeyNetworkKeyID:
            print("Tranport Key (Standard Network Key) Command detected")
            return True

    def checkInsecureRejoin(self):
        if self.zigbeepacket.cmd_id == Constants.CONST_InsecureRejoinResponse and \
                self.zigbeepacket.cmd_rejoin_status == Constants.CONST_InsecureRejoinStatusSuccess:
            return self.dbCon.checkDBifInsecureRejoin(self.zigbeepacket)

    def checkTouchlinkCommissioningAttack(self, userPANID):
        #check if Network JOIN Request
        if self.zigbeepacket.zcl_command_id == Constants.CONST_ZLLNetworkJoinRouterRequest or \
                self.zigbeepacket.zcl_command_id == Constants.CONST_ZLLNetworkJoinEndDeviceRequest:
            print("Network Join detected")

            #check PAN ID of User
            if len(userPANID) == 0:
                return True

            if userPANID == self.zigbeepacket.pan_source:
                return True

        return False
