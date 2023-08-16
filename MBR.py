##########################################################################################
#    
#    Assignment 2: Forensics - MBR
#    
#     Takes an ISO file (containing the dump of just the MBR from a drive with multiple partitions) and finds:
#     ----1. The number of partitions
#     ----2. The type of each partition
#     ----3. The starting address of each partition (LBA)
#     ----4. The size of each partition (in sectors)
#
###########################################################################################

# Import necessary modules
import sys
import csv
from hashlib import sha256

# Define constants
FILE = 'mbr_dump.iso'  # Input ISO file
PARTITION_TYPE = 'mbr_partition_types.csv'  # Partition type information
CHECKSUM = "a8a0e1dd8799459e6288b918d16b6efe2ef68809c7084f2dc968ec967d4574f3"  # Expected checksum

def mbr():
    # MBR partition table starts at byte 446
    pointer = 446

    # Initialize the number of partitions
    partitionNum = 0

    # Count the number of partitions based on the system indicator
    while hexList[pointer+4] != "00":
        partitionNum += 1
        pointer += 16

    # Reset the current pointer
    pointer = 446

    print("\nNumber of partitions: {}".format(partitionNum))

    for i in range(partitionNum):
        # Get the partition type from the partitionType dictionary
        pointerParType = partitionType[str(hexList[pointer+4]).upper()]

        # Get the partition address (LBA)
        hexStr = str(hexList[pointer+11]+hexList[pointer+10]+hexList[pointer+9]+hexList[pointer+8])
        LBA = int(hexStr, 16)

        # Get the size of the partition (in sectors)
        hexString = str(hexList[pointer+15]+hexList[pointer+14]+hexList[pointer+13]+hexList[pointer+12])
        sizeOfParSect = int(hexStr, 16)

        print("------------------------------------------------------------------")
        print("Partition {} Details:".format(i+1))
        print("Partition Type: \"{}\"".format(pointerParType))
        print("Partition Address (LBA): {}".format(LBA))
        print("Number of Sectors in Partition: {}".format(sizeOfParSect))
        print("------------------------------------------------------------------")

        # Move to the next partition
        pointer += 16

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

# Call the 'mbr' function to process the MBR partition table
mbr()