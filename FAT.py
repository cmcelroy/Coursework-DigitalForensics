##########################################################################################
#    
#    Assignment 2: Forensics - FAT32    
#     Takes an ISO file (containing the dump of just the FAT32 from a drive with multiple partitions) and finds:
#       ----1. The number of sectors per cluster
#       ----2. The number of bytes per sector
#       ----3. The size of the reserved area in sectors
#       ----4. The number of FATs
#       ----5. The size of each FAT in sectors
#       ----6. The cluster address of the root directory
#       ----7. The starting sector address of the data section
#       ----8. The cluster address of the directory entry for the directory name
#       ----9. The cluster address of the file data for the file name
#       ----10. The size of the file in bytes
#       ----11. The ending cluster address of the file
#
###########################################################################################


import sys
import csv
from hashlib import sha256

FILE = 'FAT_FS.iso'
CHECKSUM = "04b608cd055d02da1d85b19cae97c91912d4a98bd2f7b17335fefdbcf0a34e2f"

SEARCH_DIRECTORY = "Photos"
SEARCH_FILE = "homework"

def fat32():
    
    # bytes per sector
    bytesSect = int(hexList[12]+hexList[11], 16)
    # sectors per cluster
    clusterSect = int(hexList[13], 16)
    # size of area in sectors
    resArea = int(hexList[15]+hexList[14], 16)
    # start address of 1st FAT
    startAddr = resArea
    # of FATs
    numFats = int(hexList[16], 16)
    # sectors per FAT
    sectFAT = int(hexList[39]+hexList[38]+hexList[37]+hexList[36], 16)
    # cluster addr of root directory
    clusterAddrRoot = int(hexList[47]+hexList[46]+hexList[45]+hexList[44], 16)
    # starting sector addr of root directory
    startSectAddr = (sectFAT * numFats) + resArea
    # go to root first entry
    cluster = (startSectAddr * bytesSect) + 32
    pointerFirst = cluster

    # cycles enties
    while pointerFirst < cluster * 2:
        if hexList[pointerFirst] == "00":
            print "File not found."
            exit()

        # translates first 8 bytes
        fileName = hexList[pointerFirst]+hexList[pointerFirst+1]+hexList[pointerFirst+2]+hexList[pointerFirst+3]+hexList[pointerFirst+4]+hexList[pointerFirst+5]+hexList[pointerFirst+6]+hexList[pointerFirst+7]
        fileName = fileName.decode("hex")

        # "checks if directory name is a substring of 1st 8 bytes?"
        if SEARCH_DIRECTORY.upper() not in fileName:
            pointerFirst += 32
        else:
            break
    
    # cluster address of directory
    dirEntryAddr = int(hexList[pointerFirst+21]+hexList[pointerFirst+20]+hexList[pointerFirst+27]+hexList[pointerFirst+26], 16)
    cluster += 512
    pointerNext = cluster

    #searches for file name
    while pointerNext < cluster * 2:
        if hexList[pointerNext] == "00":
            print "File not found."
            exit()

        # translating first 8 bytes
        fileName = hexList[pointerNext]+hexList[pointerNext+1]+hexList[pointerNext+2]+hexList[pointerNext+3]+hexList[pointerNext+4]+hexList[pointerNext+5]+hexList[pointerNext+6]+hexList[pointerNext+7]
        fileName = fileName.decode("hex")

        # "is the directory name" a substring of those 8 bytes?
        if SEARCH_FILE.upper() not in fileName:
            pointerNext += 32
        else:
            # if it is, we found it. proceed...
            break

    # cluster address of file data
    fileEntryAddr = int(hexList[pointerNext+21]+hexList[pointerNext+20]+hexList[pointerNext+27]+hexList[pointerNext+26], 16)

    # size of this file
    sizeOfFile = int(hexList[pointerNext+31]+hexList[pointerNext+30]+hexList[pointerNext+29]+hexList[pointerNext+28], 16)
    fatTable = startAddr * bytesSect

    # first entry of FAT
    offset = fatTable + (fileEntryAddr * 4)
    counter = 0
    curCluster = hexList[offset+3]+hexList[offset+2]+hexList[offset+1]+hexList[offset]
    # next cluster
    while curCluster != "0fffffff":
        offset = fatTable + (int(curCluster, 16) * 4)
        curCluster = hexList[offset+3]+hexList[offset+2]+hexList[offset+1]+hexList[offset]
        counter += 1
    # end of cluster
    endClusterAddr = counter + 4 + 1

    print "------------------------------------------------------------------"
    print "Bytes/Sector: {}".format(bytesSect)
    print "Sectors/Cluster: {}".format(clusterSect)
    print "Size of Reserved Area in Sectors: {}".format(resArea)
    print "Start Address of 1st FAT: {}".format(startAddr)
    print "# of FATs: {}".format(numFats)
    print "Sectors/FAT: {}".format(sectFAT)
    print "Cluster Address of Root Directory: {}".format(clusterAddrRoot)
    print "Starting Sector Address of the Data Section: {}".format(startSectAddr)
    print "Cluster Address of Directory Entry: {}".format(dirEntryAddr)
    print "Cluster Address of File Data: {}".format(fileEntryAddr)
    print "Size of File in Bytes: {}".format(sizeOfFile)
    print "Ending Cluster Address of File: {}".format(endClusterAddr)
    print "------------------------------------------------------------------"

with open(FILE, 'r') as f:
    isoFile = f.read()

hexList = ["{:02x}".format(ord(i)) for i in isoFile]


fat32()