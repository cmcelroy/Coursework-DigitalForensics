##########################################################################################
#    
#    Assignment 3: Forensics - File Carving    
#     
#    Description:  Uses two methods to locate and extract image files.
#
###########################################################################################




# Import necessary modules
import sys
import csv
import pathlib
from hashlib import sha256

# Define constants
FILE = 'FAT_Corrupted.iso'  # Input ISO file
CHECKSUM = "0f67d2b58b4ec406dcb09fd4542d55a6e0151cc06cc5925d710068b4d2b9a3f1"  # Expected checksum
BLOCK = 16
REC_FILES = "Recovered_Image_"  # Prefix for recovered image files
JPEG_START = "ffd8ff"  # Start marker for JPEG images
JPEG_END = "ffd9"  # End marker for JPEG images
JPEG_BLOCK = 512  # Block size for JPEG images
IMG_COUNT = 0  # Counter for recovered image files

# Method 1: Using file system information to recover images
def meth1():
    # Extract file system information
    bytesSect = int(hexList[12]+hexList[11], BLOCK)
    clusterSect = int(hexList[13], BLOCK)
    resArea = int(hexList[15]+hexList[14], BLOCK)
    startAddr = resArea
    numFats = int(hexList[16], BLOCK)
    sectFAT = int(hexList[39]+hexList[38]+hexList[37]+hexList[36], BLOCK)
    clusterAddrRoot = int(hexList[47]+hexList[46]+hexList[45]+hexList[44], BLOCK)
    startSectAddr = (sectFAT * numFats) + resArea
    fileStartAddr = []
    fileEndAddr = []
    fileEntryAddr = bytesSect * startAddr
    fileOffset = 0
    fileSect = 0
    pointer = (startSectAddr * bytesSect)
    count = 0
    
    # Iterate through the ISO file
    while pointer < len(hexList):
        hexSeries = hexList[pointer]+hexList[pointer+1]+hexList[pointer+2]
        
        if hexSeries == JPEG_START:
            fileStartAddr.append(pointer)
            fileEndAddr.append(pointer+JPEG_BLOCK)
            count += 1
            name = REC_FILES+'image%02d.jpg' % count
            writefile = open(name, 'wb')
            print "File {} : Starting Address: {}".format(count, pointer)
            fileSect += 1
            print "           Starting Sector: {}".format(fileSect)
            print "           Cluster Address: {}".format(fileSect+2) 
            pointer += 512
        else:
            pointer += 512
            fileSect += 1

    print "------------------------------------------------------------------"
    print "--------------------------SUMMARY---------------------------------"
    print "------------------------------------------------------------------"
    print "Bytes/Sector: {}".format(bytesSect)
    print "Sectors Per Cluster: {}".format(clusterSect)
    print "Size of Reserved Area in Sectors: {}".format(resArea)
    print "Start Address of 1st FAT: {}".format(startAddr)
    print "# of FATs: {}".format(numFats)
    print "Sectors/FAT: {}".format(sectFAT)
    print "Cluster Address of Root Directory: {}".format(clusterAddrRoot)
    print "Starting Sector Address of the Data Section: {}".format(startSectAddr)
    print "Number of Files Found: {}".format(count)
    print "------------------------------------------------------------------"

# Method 2: Using header signatures to recover images
def meth2():
    global IMG_COUNT
    count = 0
    file = open(FILE, 'rb')
    data = file.read(BLOCK)
    
    # Iterate through the ISO file using block reading
    while data != '':
        location = findHeaders(data)
        relative_location = location - BLOCK + file.tell()
        if location >= 0:
            print "File {} : Starting Address: {}".format(IMG_COUNT, relative_location)
            writeImage(file, relative_location, REC_FILES)
            IMG_COUNT = IMG_COUNT + 1
        data = file.read(BLOCK)

# Function to find the start of a JPEG header within data
def findHeaders(data):
    length = len(data)
    for i in range(0, length - 3):
        if data[i] == '\xff':
            if data[i+1:i+4] == '\xd8\xff\xe0' or data[i+1:i+4] == '\xd8\xff\xe1':
                return i
    return -1

# Function to find the end of a JPEG image within data
def findTermination(data):
    length = len(data)
    for i in range(0, length - 1):
        if data[i] == '\xff' and data[i+1] == '\xd9':
            return i + 1
    return -1

# Function to write the recovered image to a file
def writeImage(file, location, REC_FILES):
    file.seek(location)
    global JPEG_BLOCK
    global IMG_COUNT
    name = REC_FILES + 'image%02d.jpg' % IMG_COUNT
    writefile = open(name, 'wb')
    
    data = file.read(JPEG_BLOCK)
    while True:
        writefile.write(data)
        data = file.read(JPEG_BLOCK)
        location = findHeaders(data)
        termination = findTermination(data)
        if location >= 0:
            break
        elif termination >= 0:
            break
        elif data == '':
            break
    file.seek(file.tell() - JPEG_BLOCK)
    writefile.close()
    print 'Successfully Recovered : {}'.format(name)

print "------------------------------------------------------------------"
method = str(input("Please choose a carving method, either -1 or -2\nMethod: "))
print "File is being analyzed.."

# Read the content of the ISO file and convert it to a list of hexadecimal strings
with open(FILE, 'r') as f:
    iso = f.read()

hexList = ["{:02x}".format(ord(i)) for i in iso]

# Choose and call the appropriate recovery method
if method == str(-1):
    meth1()
elif method == "-2":
    meth2()
else:
    pass