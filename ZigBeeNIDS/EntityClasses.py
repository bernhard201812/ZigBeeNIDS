"""
name: EntityClasses.py
description: class for storing the entities from the database to objects in python
-class ZigBeePacket: normalized ZigBee Object which is used for further processing. so this nids module could be easily adapted for other inputs
-class ThreadSettings: store the information if the occurance of a specific thread should trigger an notification
-class GeneralSettings: store general information like username, mailadresse which is notified, ZigBee Keys if necessary,..
author: Bernhard Bruckner - is201812
"""
import datetime


class ZigBeePacket:

    def __init__(self, packet):
        self._packet = packet
        self.id = 0
        self.nwk_source = ''
        self.nwk_source64 = ''
        self.nwk_dst = ''
        self.nwk_seqno =''
        self.cmd_addr = ''
        self.pan_source = ''
        self.pan_dst = ''
        self.zcl_command_id =''
        self.cmd_id =''
        self.nwk_frame_typ=''
        self.security =''
        self.zbee_sec_mic =''
        self.zbee_sec_counter =''
        self.zbee_aps_cmd_id =''
        self.rejoin_status =''
        self.nwk_dst64 =''
        self.zbee_aps_cmd_key_type =''
        self.creationDate =datetime.datetime.now()


    def normalizeInput(self):
        """
        method that normalize the Input in an ZigBeeNIDS Object
        :return: self
        """

        try:
            if "ZBEE_NWK" in self._packet:

                if hasattr(self._packet.zbee_nwk, "frame_type"):
                    self.nwk_frame_typ = str(self._packet.zbee_nwk.frame_type)

                if hasattr(self._packet.zbee_nwk, "dst"):
                    self.nwk_dst = str(self._packet.zbee_nwk.dst)

                if hasattr(self._packet.zbee_nwk, "src"):
                    self.nwk_source = str(self._packet.zbee_nwk.src)

                if hasattr(self._packet.zbee_nwk, "src64"):
                    self.nwk_source64 = str(self._packet.zbee_nwk.src64)

                if hasattr(self._packet.zbee_nwk, "zbee_sec_mic"):
                    self.zbee_sec_mic = str(self._packet.zbee_nwk.zbee_sec_mic.replace(':', ''))

                if hasattr(self._packet.zbee_nwk, "zbee_sec_counter"):
                    self.zbee_sec_counter = str(self._packet.zbee_nwk.zbee_sec_counter)

                # insecure rejoin packets
                if hasattr(self._packet.zbee_nwk, "cmd_rejoin_status"):
                    self.cmd_rejoin_status = str(self._packet.zbee_nwk.cmd_rejoin_status)
                    self.cmd_addr = str(self._packet.zbee_nwk.cmd_addr)

                if hasattr(self._packet.zbee_nwk, "security"):
                    self.security = str(self._packet.zbee_nwk.security)

                if hasattr(self._packet.zbee_nwk, "cmd_id"):
                    self.cmd_id = str(self._packet.zbee_nwk.cmd_id)

                if hasattr(self._packet.zbee_nwk, "seqno"):
                    self.nwk_seqno = str(self._packet.zbee_nwk.seqno)

            self.creationDate = datetime.datetime.now()

            if "WPAN" in self._packet:
                if hasattr(self._packet.wpan, "src64"):
                    self.nwk_source64 = str(self._packet.wpan.src64)

                    if self.nwk_source == '':
                        self.nwk_source = self.nwk_source64

                if hasattr(self._packet.wpan, "dst64"):
                    self.nwk_dst64 = str(self._packet.wpan.dst64)

                    if self.nwk_dst == '':
                        self.nwk_dst = self.nwk_dst64

                if hasattr(self._packet.wpan, "dst_pan"):
                    self.pan_dst = str(self._packet.wpan.dst_pan)

                if self.nwk_seqno == '' and hasattr(self._packet.wpan, "seq_no"):
                    self.nwk_seqno = str(self._packet.wpan.seq_no)

                if hasattr(self._packet.wpan, "src_pan"):
                    self.pan_source = str(self._packet.wpan.src_pan)

                # if compression equals 1 src and dst pan is equal
                if hasattr(self._packet.wpan, "pan_id_compression") and self._packet.wpan.pan_id_compression == 1:
                    self.pan_source = str(self.pan_dst)


            if "ZBEE_ZCL" in self._packet:
                if hasattr(self._packet.zbee_zcl, "zbee_zcl_general_touchlink_rx_cmd_id"):
                    self.zcl_command_id = str(self._packet.zbee_zcl.zbee_zcl_general_touchlink_rx_cmd_id)
                    self.cmd_id = self.zcl_command_id

           # Transport Key Command
            if "ZBEE_APS" in self._packet:
                if hasattr(self._packet.zbee_aps, "zbee_aps.cmd_id"):
                    self.zbee_aps_cmd_id = str(self._packet.zbee_aps.cmd_id)
                if hasattr(self._packet.zbee_aps, "zbee_aps.cmd_key_type"):
                    self.zbee_aps_cmd_key_type = str(self._packet.zbee_aps.cmd_key_type)

                # log 802.15.4 data
            #if "DATA" in self._packet:
            #    if hasattr(self._packet.data, "data.data"):
            #        self.data_data = str(self._packet.data.data)

            #empty packets should be skipped
            if self.nwk_dst == '' and self.nwk_source == '' and self.zbee_sec_mic == '' and self.zbee_sec_counter == '':
                return

            return self
        except:
            pass


class ThreadSettings:
    """
    class to save the settings of the attack
    """
    def __init__(self, id, name, shouldAlert):
        self.id = id
        self.name = name
        self.shouldAlert = shouldAlert

class GeneralSettings:
    """
    class for general settings like PANID and Mailaddress
    """
    def __init__(self, id, name, value):
        self.id = id
        self.name = name
        self.value = value
