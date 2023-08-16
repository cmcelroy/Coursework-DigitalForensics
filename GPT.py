##########################################################################################
#    
#    Assignment 2: Forensics - GPT
#    
#     Takes an ISO file (containing the dump of just the GPT from a drive with multiple partitions) and finds:
#     ----1. The number of partitions
#     ----2. The name of each partition
#     ----2. The type of each partition
#     ----3. The starting address of each partition
#     ----4. The size of each partition in sectors, or the ending sector address of each partition for this one.
#
###########################################################################################



# Import necessary modules
import sys
import csv
from hashlib import sha256

# Define constants
FILE = 'gpt_dump.iso'  # Input ISO file
PARTITION_TYPE = 'gpt_partition_guids.csv'  # Partition type information
CHECKSUM = "5bf5860dfda9dd8cd13eb6d001c6667c43be34424bbf60bc62a722479c0bfb14"  # Expected checksum

def gpt():
    # GPT partition starts at byte 512, so add an additional 512 for the partition table
    pointer = 1024

    partitionNum = 0

    # Get the number of partitions based on partition entry locations every 128 bytes
    while pointer < len(hexList) and hexList[pointer] != "00":
        partitionNum += 1
        pointer += 128

    # Reset the pointer
    pointer = 1024

    print("\nNumber of partitions: {}".format(partitionNum))

    for i in range(partitionNum):
        # Extract the GUID (Globally Unique Identifier) for the partition
        guid = (hexList[pointer+3]+hexList[pointer+2]+hexList[pointer+1]+hexList[pointer]+"-"+hexList[pointer+5]+hexList[pointer+4]+"-"+hexList[pointer+7]+hexList[pointer+6]+"-"\
            +hexList[pointer+8]+hexList[pointer+9]+"-"+hexList[pointer+10]+hexList[pointer+11]+hexList[pointer+12]+hexList[pointer+13]+hexList[pointer+14]+hexList[pointer+15]).upper()

        # Extract the starting LBA (Logical Block Address) for the partition
        hexStr = ""
        for j in range(pointer+39, pointer+31, -1):
            hexStr += str(hexList[j])
        LBA_START = int(hexStr, 16)

        # Extract the ending LBA address for the partition
        hexString = str(hexList[pointer+47]+hexList[pointer+46]+hexList[pointer+45]+hexList[pointer+44]+hexList[pointer+43]+hexList[pointer+42]+hexList[pointer+41]+hexList[pointer+40])
        LBA_END = int(hexStr, 16)

        # Extract the name of the partition
        nameChar = pointer+56
        name = ""
        while hexList[nameChar] != "00":
            name += hexList[nameChar]
            nameChar += 2
        name = name.decode("hex")  # Convert hexadecimal to ASCII

        pointer += 128  # Move to the next partition entry

        print("------------------------------------------------------------------")
        print("Partition {} Details:".format(i+1))
        print("Partition Name: {}".format(name))
        print("Partition GUID: {}".format(guid))
        print("Partition Type: {}".format(partitionType[guid]))
        print("Partition Starting Address: {}".format(LBA_START))
        print("Partition Ending Address: {}\n".format(LBA_END))
        print("------------------------------------------------------------------")

# Read the content of the ISO file and convert it to a list of hexadecimal strings
with open(FILE, 'r') as f:
    isoFile = f.read()

hexList = ["{:02x}".format(ord(c)) for c in isoFile]

# Create a dictionary to store partition type information
partitionType = {}
with open(PARTITION_TYPE, mode='r') as csvfile:
    entries = csv.reader(csvfile, delimiter=',')
    for row in entries:
        partitionType[row[0]] = row[1]

# Call the 'gpt' function to process the GPT partition table
gpt()