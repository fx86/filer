'''
Copyright (c) 2014 Chet Hosmer
 
Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.
 
'''
# 
# Python QUICK FISH File System Hash Program
# Author: C. Hosmer
#         New ideas and new hashing selection by Michelle Mullinix
#         Adding a hash search capability from Greg Dominguez
#
# Revised: 11/1/2014 from the original pfish program in Python Forensics Book 
#                    ISBN: 978-0124186767
#                    New ideas and expansion inspired by Michelle Mullinix and Greg Dominguez
#                    Updates Include:
#                        a) Reduced the script to a single .py file for simple execution
#                        b) Allowed selection of one or (optionally) two hash types per run
#                        c) Supported all native hash types available in Python's hashlib
#                        d) Added the optional capability to include a hashmatch input file
#                           this will add two fields to the csv output file (Match and ID) 
#                           that contains the word FOUND when a match is identified
#                           along with the ID value associated with the hash from the input file. 
#                           Note the input file format for the hashmatch is strict  
#                           HASHVALUE,ID one entry per line.  
# Version 1.0
#
 
import logging    # Python Standard Library Logger
import time       # Python Standard Library time functions
import sys        # Python Standard Library system specific parameters
import os         # Python Standard Library - Miscellaneous operating system interfaces
import stat       # Python Standard Library - constants and functions for interpreting os results
import time       # Python Standard Library - Time access and conversions functions
import hashlib    # Python Standard Library - Secure hashes and message digests
import argparse   # Python Standard Library - Parser for command-line options, arguments
import csv        # Python Standard Library - reader and writer for csv files
 
# Support Functions Start Here, Main Script Entry is at the bottom
 
#
# Name: ParseCommand() Function
#
# Desc: Process and Validate the command line arguments
#           use Python Standard Library module argparse
#
# Input: none
#  
# Actions: 
#              Uses the standard library argparse to process the command line
#              establishes a global variable gl_args where any of the functions can
#              obtain argument information
#
def ParseCommandLine():
 
    parser = argparse.ArgumentParser('Python file system hashing .. QuickFish')
 
    parser.add_argument('-v', "--verbose",  help="allows progress messages to be displayed", action='store_true')
 
    # setup a group where the selection is mutually exclusive and required.
 
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--md5',      help = 'specifies MD5 algorithm',      action='store_true')
    group.add_argument('--sha1',     help = 'specifies SHA1 algorithm',     action='store_true')  
    group.add_argument('--sha224',   help = 'specifies SHA224 algorithm',   action='store_true')  
    group.add_argument('--sha256',   help = 'specifies SHA256 algorithm',   action='store_true')  
    group.add_argument('--sha384',   help = 'specifies SHA384 algorithm',   action='store_true')  
    group.add_argument('--sha512',   help = 'specifies SHA512 algorithm',   action='store_true')   
 
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--md5a',      help = 'specifies MD5 algorithm',      action='store_true')
    group.add_argument('--sha1a',     help = 'specifies SHA1 algorithm',     action='store_true')  
    group.add_argument('--sha224a',   help = 'specifies SHA224 algorithm',   action='store_true')  
    group.add_argument('--sha256a',   help = 'specifies SHA256 algorithm',   action='store_true') 
    group.add_argument('--sha384a',   help = 'specifies SHA384 algorithm',   action='store_true')  
    group.add_argument('--sha512a',   help = 'specifies SHA512 algorithm',   action='store_true')   
 
    parser.add_argument('-d', '--rootPath',   type= ValidateDirectory,         required=True, help="specify the root path for hashing")
    parser.add_argument('-r', '--reportPath', type= ValidateDirectoryWritable, required=True, help="specify the path for reports and logs will be written")   
    parser.add_argument('-m', '--hashMatch',  type= ValidateFileReadable,      required=False,help="specify the optional hashmatch input file path")   
 
    # create a global object to hold the validated arguments, these will be available then
 
    global gl_args
    global gl_hashType
    global gl_hashTypeAlt
    global gl_hashMatch
    global gl_hashDict
 
    gl_args = parser.parse_args()   
 
    # Determine the hash type(s) selected 
 
    # Mandatory
 
    if gl_args.md5:
        gl_hashType = 'MD5'
 
    elif gl_args.sha1:
        gl_hashType = 'SHA1'    
 
    elif gl_args.sha224:
        gl_hashType = 'SHA224'       
 
    elif gl_args.sha256:
        gl_hashType = 'SHA256'
 
    elif gl_args.sha384:
        gl_hashType = 'SHA384'   
 
    elif gl_args.sha512:
        gl_hashType = 'SHA512'
 
    else:
        gl_hashType = "Unknown"
        logging.error('Unknown Hash Type Specified')
 
    # Optional Type
 
    if gl_args.md5a:
        gl_hashTypeAlt = 'MD5'
 
    elif gl_args.sha1a:
        gl_hashTypeAlt = 'SHA1'    
 
    elif gl_args.sha224a:
        gl_hashTypeAlt = 'SHA224'       
 
    elif gl_args.sha256a:
        gl_hashTypeAlt = 'SHA256'
 
    elif gl_args.sha384a:
        gl_hashTypeAlt = 'SHA384'   
 
    elif gl_args.sha512a:
        gl_hashTypeAlt = 'SHA512'
    else:
        gl_hashTypeAlt = 'None'
 
    # Check for hashMatch Selection    
    if gl_args.hashMatch:
        # Create a dictionary from the input file
        gl_hashMatch = gl_args.hashMatch
        gl_hashDict = {}
 
        try:
            with open(gl_hashMatch) as fp:
                # for each line in the file extract the hash and id
                # then store the result in a dictionary
                # key, value pair
                # in this case the hash is the key and id is the value
 
                for line in fp:
                    hashKey = line.split(',')[0].upper()
                    hashID  = line.split(',')[1]
                    # Strip the newline from the ID
                    hashID  = hashID.strip()
                    # Add the key value pair to the dictionary
                    gl_hashDict[hashKey] = hashID
 
        except:
            logging.error("Failed to read in Hash List")
            DisplayMessage("Failed to read in Hash List")
    else:
        gl_hashMatch = False
 
    DisplayMessage("Command line processed: Successfully")
 
    return
 
# End ParseCommandLine============================================================      
 
#
# Name: ValidateDirectory Function
#
# Desc: Function that will validate a directory path as 
#           existing and readable.  Used for argument validation only
#
# Input: a directory path string
#  
# Actions: 
#              if valid will return the Directory String
#
#              if invalid it will raise an ArgumentTypeError within argparse
#              which will inturn be reported by argparse to the user
#
 
def ValidateDirectory(theDir):
 
    # Validate the path is a directory
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')
 
    # Validate the path is readable
    if os.access(theDir, os.R_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not readable')
 
#End ValidateDirectory ===================================
 
#
# Name: ValidateDirectoryWritable Function
#
# Desc: Function that will validate a directory path as 
#           existing and writable.  Used for argument validation only
#
# Input: a directory path string
#  
# Actions: 
#              if valid will return the Directory String
#
#              if invalid it will raise an ArgumentTypeError within argparse
#              which will inturn be reported by argparse to the user
#
 
def ValidateDirectoryWritable(theDir):
 
    # Validate the path is a directory
    if not os.path.isdir(theDir):
        raise argparse.ArgumentTypeError('Directory does not exist')
 
    # Validate the path is writable
    if os.access(theDir, os.W_OK):
        return theDir
    else:
        raise argparse.ArgumentTypeError('Directory is not writable')
 
#End ValidateDirectoryWritable ===================================
 
#
# Name: ValidateFileReadable Function
#
# Desc: Function that will validate a file path as 
#       existing and readable.  Used for argument validation only
#
# Input: a file path
#  
# Actions: 
#              if valid will return the FilePath
#
#              if invalid it will raise an ArgumentTypeError within argparse
#              which will inturn be reported by argparse to the user
#
 
def ValidateFileReadable(theFile):
 
    # Validate the path is a file
    if not os.path.isfile(theFile):
        raise argparse.ArgumentTypeError('File does not exist')
 
    # Validate the path is readable
    if os.access(theFile, os.R_OK):
        return theFile
    else:
        raise argparse.ArgumentTypeError('File is not readable')
 
#End ValidateFileReadable ===================================
 
#
# Name: WalkPath() Function
#
# Desc: Walk the path specified on the command line
#           use Python Standard Library module os and sys
#
# Input: none, uses command line arguments
#  
# Actions: 
#              Uses the standard library modules os and sys
#              to traverse the directory structure starting a root
#              path specified by the user.  For each file discovered, WalkPath
#              will call the Function HashFile() to perform the file hashing
#
 
def WalkPath():
 
    processCount = 0
    errorCount = 0
 
    oCVS = _CSVWriter(gl_args.reportPath+'fileSystemReport.csv', gl_hashType, gl_hashTypeAlt)
 
    # Create a loop that process all the files starting
    # at the rootPath, all sub-directories will also be
    # processed
 
    logging.info('Root Path: ' + gl_args.rootPath)
 
    for root, dirs, files in os.walk(gl_args.rootPath):
 
        # for each file obtain the filename and call the HashFile Function
        for file in files:
            fname = os.path.join(root, file)
            result = HashFile(fname, file, oCVS)
 
            # if hashing was successful then increment the ProcessCount
            if result is True:
                processCount += 1
            # if not sucessful, the increment the ErrorCount
            else:
                errorCount += 1      
 
    oCVS.writerClose()
 
    return(processCount)
 
#End WalkPath==================================================
 
#
# Name: HashFile Function
#
# Desc: Processes a single file which includes performing a hash of the file
#           and the extraction of metadata regarding the file processed
#           use Python Standard Library modules hashlib, os, and sys
#
# Input: theFile = the full path of the file
#           simpleName = just the filename itself
#  
# Actions: 
#              Attempts to hash the file and extract metadata
#              Call GenerateReport for successful hashed files
#
def HashFile(theFile, simpleName, o_result):
 
    # Verify that the path is valid
    if os.path.exists(theFile):
 
        #Verify that the path is not a symbolic link
        if not os.path.islink(theFile):
 
            #Verify that the file is real
            if os.path.isfile(theFile):
 
                try:
                    #Attempt to open the file
                    f = open(theFile, 'rb')
                except IOError:
                    #if open fails report the error
                    logging.warning('Open Failed: ' + theFile)
                    return
                else:
                    try:
                        # Attempt to read the file
                        rd = f.read()
                    except IOError:
                        # if read fails, then close the file and report error
                        f.close()
                        logging.warning('Read Failed: ' + theFile)
                        return
                    else:
                        #success the file is open and we can read from it
                        #lets query the file stats
 
                        theFileStats =  os.stat(theFile)
                        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(theFile)
 
                        #Print the simple file name
                        DisplayMessage("Processing File: " + theFile)
 
                        # print the size of the file in Bytes
                        fileSize = str(size)
 
                        #print MAC Times
                        modifiedTime = time.ctime(mtime)
                        accessTime = time.ctime(atime)
                        createdTime = time.ctime(ctime)
 
                        ownerID = str(uid)
                        groupID = str(gid)
                        fileMode = bin(mode)
 
                        #process the file hashes
 
                        if gl_args.md5:
                            #Calculate and Print the MD5
                            hash = hashlib.md5()
                            hash.update(rd)
                            hexMD5 = hash.hexdigest()
                            hashValue = hexMD5.upper()
                        elif gl_args.sha1:
                            hash = hashlib.sha1()
                            hash.update(rd)
                            hexSHA1 = hash.hexdigest()
                            hashValue = hexSHA1.upper()
                        elif gl_args.sha224:
                            hash = hashlib.sha224()
                            hash.update(rd)
                            hexSHA224 = hash.hexdigest()
                            hashValue = hexSHA224()                            
                        elif gl_args.sha256:
                            hash = hashlib.sha256()
                            hash.update(rd)
                            hexSHA256 = hash.hexdigest()
                            hashValue = hexSHA256.upper()
                        elif gl_args.sha384:
                            hash = hashlib.sha384()
                            hash.update(rd)
                            hexSHA384 = hash.hexdigest()
                            hashValue = hexSHA384.upper()
                        elif gl_args.sha512:
                            #Calculate and Print the SHA512
                            hash=hashlib.sha512()
                            hash.update(rd)
                            hexSHA512 = hash.hexdigest()
                            hashValue = hexSHA512.upper()
                        else:
                            logging.error('Hash not Selected')
                        #File processing completed
                        #Close the Active File
 
                        if gl_args.md5a:
                            #Calculate and Print the MD5 alternate
                            hash = hashlib.md5()
                            hash.update(rd)
                            hexMD5 = hash.hexdigest()
                            hashValueAlt = hexMD5.upper()
                        elif gl_args.sha1a:
                            hash = hashlib.sha1()
                            hash.update(rd)
                            hexSHA1 = hash.hexdigest()
                            hashValueAlt = hexSHA1.upper()
                        elif gl_args.sha224a:
                            hash = hashlib.sha224()
                            hash.update(rd)
                            hexSHA224 = hash.hexdigest()
                            hashValueAlt = hexSHA224.upper()
                        elif gl_args.sha256a:
                            hash = hashlib.sha256()
                            hash.update(rd)
                            hexSHA256 = hash.hexdigest()
                            hashValueAlt = hexSHA256.upper()
                        elif gl_args.sha384a:
                            hash = hashlib.sha384()
                            hash.update(rd)
                            hexSHA384 = hash.hexdigest()
                            hashValueAlt = hexSHA384.upper()
                        elif gl_args.sha512a:
                            hash = hashlib.sha512()
                            hash.update(rd)
                            hexSHA512 = hash.hexdigest()
                            hashValueAlt = hexSHA512.upper()
                        else:
                            hashValueAlt = "Not Selected"
 
                        print "================================"
                        f.close()
 
                        # Check if hash matching was selected
                        if gl_hashMatch:
                            # If yes then check to see if we have a match
                            # and if we do save the result
                            if gl_hashDict.has_key(hashValue):
                                foundValue = "Found"
                                foundID = gl_hashDict[hashValue]
                            elif gl_hashDict.has_key(hashValueAlt):
                                foundValue = "Found"
                                foundID = gl_hashDict[hashValueAlt]       
                            else:
                                foundValue = ""
                                foundID    = ""
                        else:
                            # Matching not set
                            foundValue = ""
                            foundID    = ""                            
 
                        # write one row to the output file
 
                        o_result.writeCSVRow(simpleName, foundValue, foundID, theFile, fileSize, modifiedTime, accessTime, createdTime, hashValue, hashValueAlt, ownerID, groupID, mode)
 
                        return True
            else:
                logging.warning('[' + repr(simpleName) + ', Skipped NOT a File' + ']')
                return False
        else:
            logging.warning('[' + repr(simpleName) + ', Skipped Link NOT a File' + ']')
            return False
    else:
            logging.warning('[' + repr(simpleName) + ', Path does NOT exist' + ']')        
    return False
 
# End HashFile Function ===================================
 
#==================================================
 
#
# Name: DisplayMessage() Function
#
# Desc: Displays the message if the verbose command line option is present
#
# Input: message type string
#  
# Actions: 
#              Uses the standard library print function to display the messsage
#
def  DisplayMessage(msg):
 
    if gl_args.verbose:
        print(msg)
 
    return  
 
#End DisplayMessage=====================================
 
# 
# Class: _CSVWriter 
#
# Desc: Handles all methods related to comma separated value operations
#
# Methods  constructor:     Initializes the CSV File
#                writeCVSRow:   Writes a single row to the csv file
#                writerClose:      Closes the CSV File
 
class _CSVWriter:
 
    def __init__(self, fileName, hashType, hashTypeAlt):
        try:
            # create a writer object and then write the header row
            self.csvFile = open(fileName, 'wb')
            self.writer = csv.writer(self.csvFile, delimiter=',', quoting=csv.QUOTE_ALL)
            self.writer.writerow( ('File', 'Match', 'ID', 'Path', 'Size', 'Modified Time', 'Access Time', 'Created Time', hashType, hashTypeAlt, 'Owner', 'Group', 'Mode') )
        except:
            logging.error('CSV File Failure')
 
    def writeCSVRow(self, fileName, match, matchID, filePath, fileSize, mTime, aTime, cTime, hashVal, hashValAlt, own, grp, mod):
        self.writer.writerow( (fileName, match, matchID, filePath, fileSize, mTime, aTime, cTime, hashVal, hashValAlt, own, grp, mod))
 
    def writerClose(self):
        self.csvFile.close()
 
# ------------ MAIN SCRIPT STARTS HERE -----------------
if __name__ == '__main__':
 
    QFISH_VERSION = '1.0'
 
    # Turn on Logging
    logging.basicConfig(filename='QUICKFISH.log',level=logging.DEBUG,format='%(asctime)s %(message)s')
 
    # Process the Command Line Arguments
    ParseCommandLine()
 
    # Record the Starting Time
    startTime = time.time()
 
    # Record the Welcome Message
    logging.info('')
    logging.info('Welcome to QUICKFISH version 1.0 ... New Scan Started')
    logging.info('')
    DisplayMessage('Wecome to QUICKFISH ... version '+ QFISH_VERSION + '\n')
 
    # Record some information regarding the system
    logging.info('System:  '+ sys.platform)
    logging.info('Version: '+ sys.version)
 
    # Traverse the file system directories and hash the files
    filesProcessed = WalkPath()
 
    # Record the end time and calculate the duration
    endTime = time.time()
    duration = endTime - startTime
 
    logging.info('Files Processed: ' + str(filesProcessed) )
    logging.info('Elapsed Time: ' + str(duration) + ' seconds')
    logging.info('')
    logging.info('Program Terminated Normally')
    logging.info('')
 
    DisplayMessage('Files Processed: ' + str(filesProcessed) )
    DisplayMessage('Elapsed Time: ' + str(duration) + ' seconds')
    DisplayMessage('')
    DisplayMessage("Program End")