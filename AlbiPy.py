import socket
import json
import threading
import platform
from datetime import datetime

PROBLEMS = ["'", "$", "QH", "?8", "H@", "ZP"]
HEADERS = ["Id", "UnitPriceSilver", "TotalPriceSilver", "Amount", "Tier", "IsFinished",
           "AuctionType", "HasBuyerFetched", "HasSellerFetched", "SellerCharacterId",
           "SellerName", "BuyerCharacterId", "BuyerName", "ItemTypeId", "ItemGroupTypeId",
           "EnchantmentLevel", "QualityLevel", "Expires", "ReferenceId"]


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


class datapoint:
    """ Single market datapoint including all available data from the game's api"""

    def __init__(self, data):
        # data attribute
        self.data = data[:]
        # correct silver prices
        try:
            data[1] //= 10000
        except TypeError:
            data[1] = 0
        except IndexError:
            data.insert(1, 0)

        try:
            data[2] //= 10000
        except TypeError:
            data[2] = 0
        except IndexError:
            data.insert(2, 0)

        # convert expire date to datetime obje
        try:
            data[17] = datetime.strptime(data[17][0:16], "%Y-%m-%dT%H:%M")
        except ValueError:
            data[17] = datetime(1900, 1, 1, 0, 0)
        except TypeError:
            data[17] = datetime(1900, 1, 1, 0, 0)
        except IndexError:
            ssasd = datetime(1900, 1, 1, 0, 0)
            data.insert(17, ssasd)

            
        # set attributes to data indexes
        try:
            self.Id = data[0]
        except IndexError:
            self.Id = "NULL"

        try:
            self.UnitPriceSilver = data[1]
        except IndexError:
            self.UnitPriceSilver = 0

        try:
            self.TotalPriceSilver = data[2]
        except IndexError:
            self.TotalPriceSilver = 0

        try:
            self.Amount = data[3]
        except IndexError:
            self.Amount = 0

        try:
            self.Tier = data[4]
        except IndexError:
            self.Tier = 0

        try:
            self.IsFinished = data[5]
        except IndexError:
            self.IsFinished = "false"

        try:
            self.AuctionType = data[6]
        except IndexError:
            self.AuctionType = "offer"

        try:
            self.HasBuyerFetched = data[7]
        except IndexError:
            self.HasBuyerFetched = "false"

        try:
            self.HasSellerFetched = data[8]
        except IndexError:
            self.HasSellerFetched = "false"

        try:
            self.SellerCharacterId = data[9]
        except IndexError:
            self.SellerCharacterId = "c00fd0f0-0ca0-00b0-aeaa-a00ee0f00000"

        try:
            self.SellerName = data[10]
        except IndexError:
            self.SellerName = "NULL"

        try:
            self.BuyerCharacterId = data[11]
        except IndexError:
            self.BuyerCharacterId = "a00aa0a0-0aa0-00a0-aaaa-a00aa0a00000"

        try:
            self.BuyerName = data[12]
        except IndexError:
            self.BuyerName = "NULL"

        try:
            self.ItemTypeId = data[13]
        except IndexError:
            self.ItemTypeId = "NULL"

        try:
            self.ItemGroupTypeId = data[14]
        except IndexError:
            self.ItemGroupTypeId = "NULL"

        try:
            self.EnchantmentLevel = data[15]
        except IndexError:
            self.EnchantmentLevel = 0

        try:
            self.QualityLevel = data[16]
        except IndexError:
            self.QualityLevel = 0

        try:
            self.Expires = data[17]
        except IndexError:
            self.Expires = datetime(1900, 1, 1, 0, 0)

        try:
            self.ReferenceId = data[18]
        except IndexError:
            self.ReferenceId = 'aa0000aa-00aa-00a0-aaa0-0a0a00aa00aa'


class sniffer_data:
    """ Organized sniffed market data"""

    def __init__(self, logs, parsed, malformed):
        self.logs = logs[:]
        self.parsed = parsed[:]
        self.malformed = malformed[:]

    def __getitem__(self, i):
        return self.parsed[i]

    def __len__(self):
        return len(self.parsed)

    def __str__(self):
        parsed = [{HEADERS[j]: attribute for j, attribute in enumerate(i.data)} for i in self.parsed]
        return json.dumps({"logs": self.logs, "parsed": parsed, "malformed": self.malformed})


class sniffing_thread(threading.Thread):
    """ Sniffing thread class"""

    def __init__(self, problems=PROBLEMS):

        threading.Thread.__init__(self)

        # set problems list
        self.problems = problems

        # define thread attributes
        self.n = 0
        self.e = 0
        self.parsed = []
        self.malformed = []
        self.recording = False
        self.last_parsed = True
        # log list with placeholder entry
        self.logs = [""]

        # initialize socket object
        if platform.system() != "Windows":
            self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

        # socket setup for windows environment
        if platform.system() == "Windows":
            self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW)
            self.sniffer.bind((local_ip(), 0))
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


    def run(self):

        # set recording to True
        self.recording = True

        # while the thread is set to recording, sniff and record data
        while self.recording:

            # wait for market data
            try:
                data = self.sniffer.recvfrom(1350)[0]
            except OSError:
                pass

            # remove known problematic strings from data
            data = str(data)
            for p in self.problems:
                data = data.replace(p, "")

            # partition received cleaned data into chunks
            chunks = [s[3:] for s in data.split("\\") if len(s) > 5 and ("Silver" in s or "ReferenceId" in s)]

            # processed chunks
            for chunk in chunks:
                # if this chunk is the start of a new piece of market information, add a new entry to the log
                if "{" in chunk[:4]:
                    self.logs.append(chunk[chunk.find("{"):])
                # otherwise, this chunk is assumed to be a continuation of the last chunk and is simply concatenated to the end
                elif self.logs:
                    self.logs[-1] += chunk
            
            # set last parsed to false
            self.last_parsed = False

        if not self.last_parsed:
            self.parse_data()


    def parse_data(self):
        """ Parse the data currently collected by the thread"""
        self.parsed = []
        self.malformed = []
        if not self.logs[0]:
            self.logs.pop(0)
        for i, log in enumerate(self.logs):
            try:
                self.parsed.append(datapoint(list(json.loads(log).values())))
            except json.decoder.JSONDecodeError:
                self.malformed.append(self.logs[i])
        self.last_parsed = True


    def get_data(self):
        """ Get the latest data from sniffing thread"""
        # if no logs have been recorded
        if self.logs == [""]:
            return sniffer_data([], [], [])

        # parse logs, record malformed logs, and count total logs and malformed logs
        if not self.last_parsed:
            self.parse_data()
        
        # return parsed data
        return sniffer_data(self.logs, self.parsed, self.malformed)


    def stop(self):
        """ Stop the sniffing thread"""
        self.recording = False
