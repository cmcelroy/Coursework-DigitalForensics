##########################################################################################################################
#       
#       Assingment 1: Reverse Engineering a Database Dump
#     
#       On the input of a CSV filw consisting of a database dump consisting of username, 
#       password and access time, but in hashed (encrypted) format,reverse engineers them 
#       to the original name, passowrd and time based and writes them into an output CSV file "output_DatabaseDump_Reverse.csv"
###########################################################################################################################


#  libraries
import hashlib
import uuid
import datetime

#  hardcoded namespace for UUID
namespace = uuid.UUID("d9b2d63d-a233-4123-847a-76838bf2413a")

#  declare lists
#  UUIDs
usernames = []
#  hashed passwords
passwords = []
#  timestamps
timestamps = []
#  plaintext names
names = []


# opens database_dump CSV file to create lists
file = open("database_dump.csv")
for i in file:
    line = i.split(",")
    usernames.append(line[0])
    passwords.append(line[1])
    timestamps.append(line[2].rstrip())
#  delete column headers
del usernames[0]
del passwords[0]
del timestamps[0]
file.close()


#  create list of plaintxt names from name file
file = open("names.txt")
for i in file:
    names.append(i.rstrip())
file.close()


#  converts plaintxt to uuid, compares with list, replaces uuid's with plaintxt
for i in names:
    encryptedName = uuid.uuid5(namespace, i)
    index = usernames.index(str(encryptedName))
    usernames[index] = i

#  convert dictionary entries to hashes, compares with datadumped hashes,if a match, replaces with decrypted text
file = open("dictionary.txt")
for i in file:
    hasher = hashlib.sha256(i.rstrip().encode("utf-8")).hexdigest().upper()
    try:
        index = passwords.index(hasher)
        passwords[index] = i.rstrip()
    except:
        continue
file.close()


#  takes each timestamp and converts to a date and times(-6)
for i in range(len(timestamps)):
   nuTime = datetime.datetime.fromtimestamp(int(timestamps[i]), datetime.timezone(-datetime.timedelta(hours = 6)))
   timestamps[i] = nuTime.strftime("%Y-%m-%dT%H:%M:%S%z")
   
#  creates a list of newly converted data
file = open("datadump_decrypted.csv", "w")
file.write("Username        Password        Last_Access\n")
file.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
for i in range(len(usernames)):
    file.write("%-15s %-15s %s\n" % (usernames[i], passwords[i], timestamps[i]))
file.close()