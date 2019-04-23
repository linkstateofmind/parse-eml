#####################
# .NAME
#     Parse-eml.py
#
# .SYNOPSIS
#     This parser automates analysis and extraction of indicators from EML files.
#     This process can eventually perform dynamic submission to various apis.
#     Current state outputs contents to a dictionary and then to json.
#
# .DESCRIPTION
#     If provided a path, script will recursively parse through all .eml files.
#     If provided an eml, script will parse through individual file.
#     Script returns attachments and json containing:
#     Headers, URLs, SMTP relays, content, and html.
#
# .NOTES
#     Name:        Parse-eml.py
#     Author:      Ben Leedham
#     Role:        Security Engineer
#     Created:     2018-12-23
#     Modified:    2019-03-20
#
# .USAGE
#     C:\Utilities\parse-eml.py -f "C:\\Users\\Default\\Desktop\\File\\message.eml"
#
#     C:\Utilities\parse-eml.py -p "C:\\Users\\Default\\Desktop\\Directory\\"
#
# .COMMENTS
#     Language:
#         Python 2.7.16
#     Platforms:
#         Windows 7-10, Windows 2012+
#     Architecture:
#         x86, x64 AMD
#     References:
#         https://stackoverflow.com/questions/31392361/how-to-read-eml-file-in-python
#         Original eml handling code heavily modified from user Dalen on Stack Overflow
#         Added SMTP relay, headers, json, urls, and other extraction.
#     Citations:
#         References code by Dalen (c) 2016 (MIT License via Stack Overflow)
#     Formatting:
#         PEP8 compliant via pycodestyle
#         Exceptions for lines with regular expressions
#     License:
#         MIT License, Copyright (c) 2019 Ben Leedham
#
#####################
from email import message_from_file
from email.parser import HeaderParser
from urlparse import urlparse
import os
import re
import datetime
import argparse
import traceback
import simplejson

##########################
# Variables and Arguments
#######


def parse_args():
    """Accepts path arguments for eml or directory."""
    outpath = "C:\\Utilities\\Logs"
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="Path to EML file",
                        required=False)
    parser.add_argument("-p", "--path", help="Directory holding eml files",
                        required=False)
    parser.add_argument("-o", "--out", help="Directory for results",
                        const=outpath, nargs='?', required=False,
                        default=outpath)
    args = parser.parse_args()
    return args

########################
# Utility Functions
#######


def save_file(fn, cont):
    """Saves cont to a file fn."""
    file = open(fn, "wb")
    file.write(cont)
    file.close()


def construct_name(id, fn, path):
    """Constructs a file name out of messages ID and packed file name."""
    id = id.split(".")
    id = id[0]+id[1]
    result = path + os.path.basename(id+"."+fn)
    return result


def clean(s):
    """Removes double or single quotations."""
    s = s.strip()
    if s.startswith("'") and s.endswith("'"):
        return s[1:-1]
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    """Removes < and > from HTML-like tag or e-mail address or e-mail ID."""
    if s.startswith("<") and s.endswith(">"):
        return s[1:-1]
    return s


def trim(s):
    """Removes whitespace, carriage returns, and new line characters."""
    s = s.strip().replace("\n", "").replace("\r", "")
    return s


def dedup(s):
    """
    Deduplication of a list.
    Reference: https://www.peterbe.com/plog/uniqifiers-benchmark
    """
    seen = set()
    seen_add = seen.add
    return [x for x in s if not (x in seen or seen_add(x))]

########################
# Parsing Functions
#######


def extractcontent(m, key, path):
    """
    Extracts content from an e-mail message.
    This works for multipart and nested multipart messages too.
    m   -- email.Message() or mailbox.Message()
    key -- Initial message ID (some string)
    Returns tuple(Text, Html, Files, Parts)
    Text  -- All text from all parts.
    Html  -- All HTMLs from all parts
    Files -- Dictionary mapping extracted file to message ID
    Parts -- Number of parts in original message.
    """
    Html = ""
    Text = ""
    Files = {}
    Parts = 0
    if not m.is_multipart():
        # Attachments
        if m.get_filename():
            fn = m.get_filename()
            cfn = construct_name(key, fn, path)
            Files[fn] = (cfn, None)
            if os.path.exists(cfn):
                return Text, Html, Files, 1
            save_file(cfn, m.get_payload(decode=True))
            return Text, Html, Files, 1
        # Not an attachment!
        # See where this belongs. Text, Html or some other data:
        cp = m.get_content_type()
        if cp == "text/plain":
            Text += m.get_payload(decode=True)
        elif cp == "text/html":
            Html += m.get_payload(decode=True)
        else:
            # Extract a message ID and a file name if there is one:
            # Packed file - Name contained in content-type header
            # instead of content-disposition header explicitly
            cp = m.get("content-type")
            try:
                id = clean(m.get("content-id"))
            except Exception:
                id = None
            # Find file name:
            o = cp.find("name=")
            if o == -1:
                return Text, Html, Files, 1
            ox = cp.find(";", o)
            if ox == -1:
                ox = None
            o += 5
            fn = cp[o:ox]
            fn = clean(fn)
            cfn = construct_name(key, fn, path)
            Files[fn] = (cfn, id)
            if os.path.exists(cfn):
                return Text, Html, Files, 1
            save_file(cfn, m.get_payload(decode=True))
        return Text, Html, Files, 1
    # This IS a multipart message.
    # So, we iterate over it and call content() recursively for each part.
    y = 0
    while 1:
        # If we cannot get the payload, it means we hit the end:
        try:
            pl = m.get_payload(y)
        except Exception:
            break
        # pl is a new Message object which goes back to content
        t, h, f, p = extractcontent(pl, key, path)
        Text += t
        Html += h
        Files.update(f)
        Parts += p
        y += 1
    return Text, Html, Files, Parts


def extractrelays(m):
    """Extracts values from EML for SMTP relays."""
    # From, By, With, Time
    regexFrom = 'Received: from(?P<From>[\s\S]*?)by\s(?P<By>[\s\S]*?)with(?P<With>[\s\S]*?);(?P<Time>[(\s\S)*]{32,36})(?:\s\S*?)'
    matches = re.finditer(regexFrom, m.as_string())
    relays = []
    for i in matches:
        relays.append({"From": trim(i.group('From')),
                       "By": trim(i.group('By')),
                       "With": trim(i.group('With')),
                       "Time": trim(i.group('Time'))})
    return relays


def extracturls(m, Html):
    """Extracts URLs from EML, base64-decoded HTML, and deduplicates values."""
    # Extract URLs from string-typed eml
    urllist = []
    url1 = re.findall('(https?://[\w\/\$\-\_\.\+\!\*\'\(\)]+[/A-Za-z0-9-=+~\?&;:_%\.#\*@!\(\)]+)', m.as_string())
    for ia in url1:
        ia_masked = ia.replace(".", "[.]").replace("://", "[://]")
        urllist.append(ia_masked)
    # Extract URLs from string-typed html
    url2 = re.findall('(https?://[\w\/\$\-\_\.\+\!\*\'\(\)]+[/A-Za-z0-9-=+~\?&;:_%\.#\*@!\(\)]+)', Html)
    for ib in url2:
        ib_masked = ib.replace(".", "[.]").replace("://", "[://]")
        urllist.append(ib_masked)
    url_d = dedup(urllist)
    return url_d


def extractheaders(eml, path):
    """
    Extracts defined headers containing relevant evidence.
    eml -- Message() object
    Returns list(From, To, Subject, Date, etc)
    If message doesn't contain one/more, returns empty strings.
    Appends keys for EML headers to a file, which can be used to add values.
    """
    Date = ""
    Sender = ""
    Receiver = ""
    Subject = ""
    OriginatingIP = ""
    ClientProxiedBy = ""
    MSHasAttach = ""
    ContentType = ""
    MIMEVersion = ""
    ThreadIndex = ""
    MessageID = ""
    AcceptLanguage = ""
    ContentLanguage = ""
    OrCIP = ""
    AuthenticatedSender = ""
    if eml.has_key("date"):
        Date = trim(eml["date"])
    if eml.has_key("from"):
        Sender = trim(eml["from"])
    if eml.has_key("to"):
        Receiver = trim(eml["to"])
    if eml.has_key("subject"):
        Subject = trim(eml["subject"])
    if eml.has_key("x-originating-ip"):
        OriginatingIP = trim(eml["x-originating-ip"]).replace("[","").replace("]","")
    if eml.has_key("x-clientproxiedby"):
        ClientProxiedBy = trim(eml["x-clientproxiedby"])
    if eml.has_key("X-MS-Has-Attach"):
        MSHasAttach = trim(eml["X-MS-Has-Attach"])
    if eml.has_key("Content-Type"):
        ContentType = trim(eml["Content-Type"])
    if eml.has_key("MIME-Version"):
        MIMEVersion = trim(eml["MIME-Version"])
    if eml.has_key("Thread-Index"):
        ThreadIndex = trim(eml["Thread-Index"])
    if eml.has_key("Message-ID"):
        MessageID = trim(eml["Message-ID"])
    if eml.has_key("Accept-Language"):
        AcceptLanguage = trim(eml["Accept-Language"])
    if eml.has_key("Content-Language"):
        ContentLanguage = trim(eml["Content-Language"])
    if eml.has_key("x-ms-exchange-organization-originalclientipaddress"):
        OrCIP = trim(eml["x-ms-exchange-organization-originalclientipaddress"])
    if eml.has_key("x-authenticated-sender"):
        AuthenticatedSender = trim(eml["x-authenticated-sender"])
    # Write headers out to aggregation file
    parser = HeaderParser()
    headers = parser.parsestr(eml.as_string())
    text_file = open(path+"headers.txt", "a")
    for h in headers.keys():
        text_file.write(h+"\r\n")
    text_file.close()
    # Add values to a list for cleaner output
    list = [Date, Sender, Receiver, Subject, OriginatingIP,
            AuthenticatedSender, OrCIP, ClientProxiedBy,
            MSHasAttach, ContentType, MIMEVersion,
            ThreadIndex, MessageID, AcceptLanguage, ContentLanguage]
    return list


def extractdata(msgfile, key, inc, p):
    """
    Extracts all data from e-mail and returns it as a dictionary.
    msgfile -- A file-like readable object
    key     -- Some ID string for Message. Can be a file name.
    Returns dict()
    Keys: Sender, Receiver, Subject, Date, Text, Urls, Parts, Files, etc.
    Key files will be present only when message contained binary files.
    Returns many values from EML headers for tracking over time.
    For more see __doc__ for content() and headers() functions.
    """
    m = message_from_file(msgfile)
    Relay = extractrelays(m)
    Date, Sender, Receiver, Subject, OriginatingIP, AuthenticatedSender,\
    OrCIP, ClientProxiedBy, MSHasAttach, ContentType, MIMEVersion,\
    ThreadIndex, MessageID, AcceptLanguage, ContentLanguage = extractheaders(m, p)
    Text, Html, Files, Parts = extractcontent(m, key, p)
    Urls = extracturls(m, Html)
    Msg = {"Relays": Relay,
           "Incident": inc,
           "Date": Date,
           "Sender": Sender,
           "Receiver": Receiver,
           "Subject": Subject,
           "URLs": Urls,
           "OriginatingIP": OriginatingIP,
           "AuthenticatedSender": AuthenticatedSender,
           "OriginalClientIP": OrCIP,
           "ClientProxiedBy": ClientProxiedBy,
           "MSHasAttach": MSHasAttach,
           "ContentType": ContentType,
           "MIMEVersion": MIMEVersion,
           "ThreadIndex": ThreadIndex,
           "MessageID": MessageID,
           "AcceptLanguage": AcceptLanguage,
           "ContentLanguage": ContentLanguage,
           "Parts": Parts,
           "Text": Text,
           "Html": Html}
    if Files:
        Msg["Files"] = Files
    return Msg

########################
# Main Function
#######


def main():
    """
    Run main function parsing either a file, a directory, or exit(1).
    Results in a dictionary, exported files, exported html.
    Structured data returned in JSON format.
    """
    args = parse_args()
    if args.file is not None:
        try:
            with open(args.file, 'rb') as f:
                name = os.path.splitext(os.path.basename(args.file))[0]
                p = args.out+"\\"+name+"\\"
                try:  
                    os.mkdir(p)
                except OSError:  
                    print ("Creation of the directory %s failed" % p)
                else:  
                    print ("Successfully created the directory %s" % p)
                t = extractdata(f, f.name, name, p)
                m = message_from_file(f)
                key = f.name
                json = simplejson.dumps(t)
                o = open(p+name+".json", "w")
                o.write(json)
                o.close()
                f.close()
        except Exception:
            print traceback.print_exc()
    elif args.path is not None:
        for subdir, dirs, files in os.walk(args.path):
            try:
                for file in files:
                    filepath = subdir + os.sep + file
                    filemain = subdir + os.sep
                    # Name equals Directory with Incident Name
                    name = os.path.basename(os.path.dirname(filepath))
                    if filepath.endswith(".eml"):
                        with open(filepath, 'rb') as f:
                            p = args.out+"\\"+name+"\\"
                            try:  
                                os.mkdir(p)
                            except OSError:  
                                print ("Creation of the directory %s failed" % p)
                            else:  
                                print ("Successfully created the directory %s" % p)
                            t = extractdata(f, f.name, name, p)
                            m = message_from_file(f)
                            key = f.name
                            json = simplejson.dumps(t)
                            o = open(p+name+".json", "w")
                            o.write(json)
                            o.close()
                            f.close()
            except Exception:
                print traceback.print_exc()
    else:
        print "Please provide a filename (-f) or directory (-p)"
        exit(1)

########################
# Run Main
#######


if __name__ == "__main__":
    main()
