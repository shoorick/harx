#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""HAR File Extractor.

* This code is a proof of concept only and is not warranted for production use
* No support is available for this software
* This code has not been audited for security issues
* Use entirely at your own risk

Notes:

    Required Python modules::

        ### python-magic module
        pip install python-magic
            or
        pip install -r requirements.txt

        Requirements for module is listed in ./requirements.txt.

    Configuration
        None
"""

#////////////////////////////////////////////////////////////////////////////////////
# HAR File Extractor
# Author: Ruan Müller
#////////////////////////////////////////////////////////////////////////////////////

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import argparse
import csv
import json
import magic
import os
import sys
import base64
import posixpath
import hashlib
# import codecs

# Python 3/2 alternative
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

# -----------------------------------------------------------------------------
# Write CSV
# -----------------------------------------------------------------------------
def writeCSV(file, objects):
    """Write CSV"""
    f = csv.writer(open(file, 'wb+'))

    ### write header
    f.writerow(['index', 'time', 'method', 'mimetype', 'size', 'url'])

    idx = 0

    while idx != len(objects):
        f.writerow([
            idx,
            objects[idx]['time'],
            objects[idx]['method'],
            objects[idx]['mimeType'],
            objects[idx]['size'],
            objects[idx]['url']])

        idx += 1


# -----------------------------------------------------------------------------
# Create Directory
# -----------------------------------------------------------------------------
def createDir(path):
    """Create directory."""
    if not os.path.exists(path):
        os.makedirs(path)


# -----------------------------------------------------------------------------
# Get File Magic
# -----------------------------------------------------------------------------
def getMagic(fileName):
    """Get file magic."""

    mime = magic.Magic(mime=True)
    mimeType = mime.from_file(fileName)

    return mimeType


# -----------------------------------------------------------------------------
# Get Object List
# -----------------------------------------------------------------------------
def getObjects(har):
    """Generate file asset list"""

    objects = dict()
    idx = 0

    for entry in har['log']['entries']:

        url = entry['request']['url']
        time = entry['startedDateTime']
        method = entry['request']['method']
        mimeType = entry['response']['content']['mimeType']
        size = entry['response']['content']['size']

        if 'text' in entry['response']['content']:
            content = entry['response']['content']['text']
        else:
            content = ''

        objects[idx] = {}
        objects[idx]['time'] = time
        objects[idx]['method'] = method
        objects[idx]['mimeType'] = mimeType
        objects[idx]['content'] = content
        objects[idx]['size'] = size
        objects[idx]['url'] = url

        idx += 1

    return objects


# -----------------------------------------------------------------------------
# Print Object List
# -----------------------------------------------------------------------------
def printObjects(objects):
    """Generate file asset list"""

    for i, obj in sorted(objects.items()):

        print(
            '[%3s] [%s] [%6s] [%30s] [Size: %8s]  [%s]' % (
                i,
                obj['time'], obj['method'], obj['mimeType'],
                obj['size'], obj['url']
            )
        )


# -----------------------------------------------------------------------------
# Get Filename From URL
# -----------------------------------------------------------------------------
def getURL(URL):
    """Get santizied URL"""

    netloc = urlparse(URL).netloc

    ### remove port
    if ':' in netloc:
        workURL = netloc.split(':')
        cleanURL =  workURL[1]
        return cleanURL
    else:
        return netloc


# -----------------------------------------------------------------------------
# Get Filename From URL
# -----------------------------------------------------------------------------
def getFilename(URL):
    """Get filename from URL"""

    path = urlparse(URL).path

    workPath = path.split('/')

    filename =  workPath[-1]

    ### generate filename based on url.file when no filename exists
    if filename == '':
        filename = getURL(URL) + ".file"

    return filename


# -----------------------------------------------------------------------------
# Generate MD5
# -----------------------------------------------------------------------------
def getMD5(fileName):
    """Generate file MD5 hash."""

    hash_md5 = hashlib.md5()

    with open(fileName, 'rb') as f:

        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


# -----------------------------------------------------------------------------
# Human redable file size
# -----------------------------------------------------------------------------
def getSize(fileName, suffix='B'):
    """Returns a human readable filesize."""

    num = os.path.getsize(fileName)

    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return '%3.1f%s%s' % (num, unit, suffix)
        num /= 1024.0

    return '%.1f%s%s' % (num, 'Yi', suffix)


# -----------------------------------------------------------------------------
# Base64 Decode Data
# -----------------------------------------------------------------------------
def getB64Decode(data):
    """Base64 Decode Data if possible."""

    try:
        result = base64.b64decode(data)
        return result
    except (TypeError, UnicodeEncodeError) as e:
        return data


# -----------------------------------------------------------------------------
# Test if data is UTF8
# -----------------------------------------------------------------------------
def getUTF8(data):
    """Test if data is UTF8"""

    try:
        result = base64.b64decode(data)
        return result
    except (TypeError, UnicodeEncodeError) as e:
        return data


# -----------------------------------------------------------------------------
# Process Object
# -----------------------------------------------------------------------------
def processObject(idx, content, filename, path, numberFiles):
    """Common Object Processing"""

    data = getB64Decode(content)

    if numberFiles:
        file = str(idx) + '-' + getFilename(filename)
    else:
        file = getFilename(filename)

    writeFile(path + file, data)
    md5 = getMD5(path + file)
    size = getSize(path + file)
    mime = getMagic(path + file)

    print(
        '[%3s] [%30s] [Size: %8s] [%s] [%30s] [%s]' % \
        (idx, file[:30], size, md5, mime.decode(), objectList[idx]['url'])
        )

    return True


# -----------------------------------------------------------------------------
# Extract File Assets
# -----------------------------------------------------------------------------
def extractObject(objectList, index, path='', numberFiles=False):
    """Extract File Assets"""

    if path != '':
        ### cross platform trailing slash fix
        if path[-1] != os.sep:
            path = path + os.sep
        createDir(path)

    if index == 'all':

        idx = 0

        while idx != len(objectList):
            if 'content' in objectList[idx]:
                processObject(idx, objectList[idx]['content'], objectList[idx]['url'], path, numberFiles)
            else:
                print('[%3s] No content for object found.' % idx)

            idx += 1

    elif isinstance(index, int):

        idx = index

        if idx in objectList:
            if 'content' in objectList[idx]:
                processObject(idx, objectList[idx]['content'], objectList[idx]['url'], path, numberFiles)
            else:
                print('[%3s] No content for object found.' % index)
        else:
            print('[%3s] Object not found.' % index)


# -----------------------------------------------------------------------------
# Write File
# -----------------------------------------------------------------------------
def writeFile(file, data):
    """Write data to file."""

    with open(file, 'wb') as exportFile:
        exportFile.write(data)

    # try:
        # with codecs.open(file, 'w', 'utf8') as exportFile:
            # exportFile.write(data)
    # except (UnicodeDecodeError) as e:
        # with open(file, 'w') as exportFile:
            # exportFile.write(data)

    return True


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--csv', help='Save object list to [CSV]')
    parser.add_argument('-l', '--list', action='store_true', default=0, help='List objects')
    parser.add_argument('-x', '--eXtract', type=int, help='eXtract object matching index from -l output')
    parser.add_argument('-xa', '--eXtractAll', action='store_true', default=0, help='eXtract all objects')
    parser.add_argument('-d', '--directory', help='[DIRECTORY] to extract files to')
    parser.add_argument('-n', '--number', action='store_true', default=0, help='prepend output filename with index from -l output')
    parser.add_argument('har_file')
    args = parser.parse_args()


    ### Read HAR file
    try:
        with open(args.har_file, 'r') as har_file:
            har = json.load(har_file)
    except IndexError:
        sys.stderr.write('Usage: %s <file.har>\n' % (sys.argv[0]))
        sys.exit(1)
    except ValueError as e:
        sys.stderr.write('Invalid .har file: %s\n' % (str(e)))
        sys.exit(2)
    except (FileNotFoundError, IsADirectoryError, OSError, PermissionError) as e:
        sys.stderr.write('Cannot open file: %s\n' % (str(e)))
        sys.exit(3)

    ### Export Objects List to CSV
    if args.csv:
        objectList = getObjects(har)
        writeCSV(args.csv, objectList)

    ### List Objects
    if args.list:
        objectList = getObjects(har)
        printObjects(objectList)

    ### Extract Specific Object
    if args.eXtract:

        objectList = getObjects(har)

        if args.directory:
            extractObject(objectList, args.eXtract, args.directory, args.number)
        else:
            extractObject(objectList, args.eXtract, '', args.number)

    ### Extract All Objects
    if args.eXtractAll:

        objectList = getObjects(har)

        if args.directory:
            extractObject(objectList, 'all', args.directory, args.number)
        else:
            extractObject(objectList, 'all', '', args.number)
