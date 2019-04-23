# parse-eml
Python parser to extract EML headers, relays, urls, html, and attachments

    .NAME
        Parse-eml.py

    .SYNOPSIS
        This parser automates analysis and extraction of indicators from EML files.
        This process can eventually perform dynamic submission to various apis.
        Current state outputs contents to a dictionary and then to json.

    .DESCRIPTION
        If provided a path, script will recursively parse through all .eml files.
        If provided an eml, script will parse through individual file.
        Script returns attachments and json containing:
        Headers, URLs, SMTP relays, content, and html.

    .NOTES
        Name:        Parse-eml.py
        Author:      Ben Leedham
        Title:       Security Engineer
        Created:     2018-12-23
        Modified:    2019-03-20

    .USAGE
        C:\Utilities\parse-eml.py -f "C:\\Users\\Default\\Desktop\\File\\message.eml"
        C:\Utilities\parse-eml.py -p "C:\\Users\\Default\\Desktop\\Directory\\"

    .COMMENTS
        Language:
            Python 2.7.16
        Platforms:
            Windows 7-10, Windows 2012+
        Architecture:
            x86, x64 AMD
        References:
            https://stackoverflow.com/questions/31392361/how-to-read-eml-file-in-python
            Original eml handling code heavily modified from user Dalen on Stack Overflow
            Added SMTP relay, headers, json, urls, and other extraction.
        Citations:
            References code by Dalen (c) 2016 (MIT License via Stack Overflow)
        Formatting:
            PEP8 compliant via pycodestyle
            Exceptions for lines with regular expressions
        License:
            MIT License, Copyright (c) 2019 Ben Leedham
