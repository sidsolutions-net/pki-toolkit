#!/bin/bash

################################################################
#  Author     : Sid McLaurin
#  Copyright  : Copyright (c) SID Solutions
#  Date       : 03/25/2019
#  Version    : 1.0
#  License    : GNU General Public License
#  GitHub     : https://github.com/sidsolutions-net/pki-toolkit
#################################################################
#  Description:
# - Remote PKI Validation Script - *nix
#################################################################
# Purpose:
# - provide a network certificate validation script that
#   can take .csv input and export optional .csv report
#
# Requirements:
# - Common Name
# - LDAPv3 DN
# - Dates
# - End Date
# - Days to Expiration
# - CA chain
# - SANs entries
# - Issuer
# - Signature Algorithm
# - Serial Number
# - CRL Url
# - CA Chain validation
# - OCSP Validation
# - CRL Status
# - Layer 7
#
# Method:
# - openssl & curl with standard shell commands
#
# Usage:
# - Set date and timeout commands. See Notes
# - Provide input parameter CSV file of valid FQDN hostnames
#   and/or IP Addresses. Provide optional output file with -o
#   option. CA Chain Validation and CRL Revocation check
#   options
#
# Tested Platforms:
# - macOS Mojave 10.14.4 with OpenSSL 1.1.1b & curl 7.54.0
# - Lubuntu 18.10 with OpenSSL 1.1.1 & curl 7.61.0
#
# Notes:
# - All commands send SNI (-servername)
# - Mac & BSD will need to use gdate & gtimeout.
#   Uncomment and Comment accordingly
# - OCSP requires OpenSSL 1.1 or higher due to responders
#   requiring valid HOST HTTP Header. Blank output for
#   older version of OpenSSL when enabled.
# - LDAPv3 DN output is in commas and requires escaping
#   per platform and application. Default setting is for
#   Excel with commented escapes for Linux.
#
# Common Problems:
# - date & timeout commands not configured correctly for
#   OS / platform
# - Improper CSV input file
# - Output anomalies
#   - Non compatible versions of OpenSSL
#   - symlinked replacements for OpenSSL like LibreSSL
#   - symlinked replacements for GNU sed & awk
#
# Fixes & Enhancements:
#
# - 1.0
#   - Added OCSP validation but requires OpenSSL 1.1+ due
#     to most respondors requiring a valid HEAD HTTP
#     Headers.
#   - Added LDAPv3 DN output with escape options for
#     for Windows and Linux
#   - Lookup, CA Chain Validation, CRL Revocation Check &
#     Layer 7 Check as optional
#   - Speed option addition to leverage the first OpenSSL
#     command to retrieve and temporarily store the files for
#     processing.
#
# - 0.4
#   - Sanitize the input CSV from Windows line & carriage
#     returns
#   - getops & usage
#   - Handle CN extraction with subject in reverse
#   - Days from expiration option. Default is 30 days
#   - CA Chain validation option since not all servers send
#     their Root CA per the ding from SSL Labs so validation
#     can fail and the script performance hit of downloading
#     and manipulating files
#   - CRL Revocation check option
#   - Added curl Layer 7 Head Check
#   - Better error handling and error feedback
#
#   $Id: networkPKIValidation.sh, v 1.0
#################################################################
# Set Version Number
VERSION="1.0"

usage ()
{
echo "
Usage: `basename $0` -h -v -l -e [integer] -C -O -c -7 -S -o [file] -p file
  Options:
          - h: Show this help text
          - v: Version
          - l: Nslookup host
          - e: Set how many days before expiration flag
               Default is 30
          - C: CA Chain Validation
          - O: OCSP Revocation check. Requires OpenSSL 1.1.1
               or higher.
          - c: CRL Revocation check
          - 7: Layer 7 HTTP HEAD / check
          - S: Speed optimization
          - o: Output CSV of the results. Defaults to
               networkPKIValidation/networkPKIValidation.csv
          - p: Purge temp directory contents on exit
  Parameters:
      - file: Input CSV consiting of resolvable hostname and port
              Example (example.com,443) REQUIRED

    "
}

while getopts "hvle:COc7So:p" opt; do
  case ${opt} in
    h )
      usage
      exit 0
      ;;
    v )
      echo "Version: $VERSION"
      exit 0
      ;;
    l )
      LOOKUP="y"
      ;;
    e )
      EXPIRY=${OPTARG}
      ;;
    C )
      CACHECK="y"
      ;;
    O )
      OCSPCHECK='y'
      ;;
    c )
      CRLCHECK="y"
      ;;
    7 )
      LAYER7="y"
      ;;
    S )
      SPEED="y"
      ;;
    o )
      OUTPUT=${OPTARG}
      ;;
    p )
      PURGE="y"
      ;;
   \? )
      echo "Invalid option: $OPTARG use -h for help" 1>&2
      usage
      exit 1
      ;;
    : )
      echo "Invalid option: $OPTARG requires an argument" 1>&2
      usage
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

# Get the required input csv file:
INPUT=${1}

#### Required Initial Setup!!! #####
# GNU Utils settings for Linux & BSD
# Uncomment and Comment as required

## GNU date & timeout on Linux
#dateCommand=date
#timeoutCommand=timeout
## GNU date & timeout on Mac & BSD if not symlinked
### Better safe than sorry
#dateCommand=gdate
#timeoutCommand=gtimeout

# Validate arguements

# If the date command isn't set
if [[ -z $dateCommand ]]
  then
  echo -e "\n\033[1;33mError: dateCommand configuration required in script!\033[0m\n"
  exit 127
fi

# If the timeout command isn't set
if [[ -z $timeoutCommand ]]
  then
  echo -e "\n\033[1;33mError: timeoutCommand configuration required in script!\033[0m\n"
  exit 127
fi

## If there is no input file variable passed
if [ -z "$INPUT" ]
  then
    echo -e "\n\033[1;33mError: input CSV file parameter required!\033[0m\n"
    usage
    exit 126
fi

## If input file doesn't exist
if [ ! -f $INPUT ]
  then
    echo -e "\n\033[1;33mError: $INPUT file not found!\033[0m\n"
    usage
    exit 1
fi

## If input file isn't readable
if [ ! -r "$INPUT" ]
  then
    echo -e "\n\033[1;33mError: $INPUT not readable. Check permissions, exiting\033[0m\n"
    exit 126
fi

## If the input and output are the same
if [[ "$INPUT" == "$OUTPUT" ]]
  then
    echo -e "\n\033[1;33mCan't read and write to the same file!\033[0m"
    echo -e  "\033[1;33mInfile: \033[0m$INPUT \033[1;33mOutfile: \033[0m$OUTPUT\033[0m\n"
    exit 1
fi

# Print Ad
echo -e "\n\033[1;33mSID Solutions\n"
sleep 0.5
echo -e "\033[1;33mS\033[1;34molid\033[1;33m I\033[1;34mnnovative\033[1;33m D\033[1;34mesigned\033[1;33m Solutions\n"
echo -e "\033[0mProviding tomorrow's solutions, today"
echo
sleep 1

# Temporay directory
tempDir="networkPKIValidation"

if [ -d "$tempDir" ]
  then
    rm -f $tempDir/*.*
  else
    mkdir $tempDir
fi

# Sanitize input file from Windows line feed and carriage returns
tr -d '\15\32' < $INPUT > $tempDir/$INPUT
mv $tempDir/$INPUT $INPUT

# Default output file
if [ -z "$OUTPUT" ]
  then
    OUTPUT=$tempDir/networkPKIValidation.csv
fi

# Default days before expiration
if [ -z $EXPIRY ]
  then
    EXPIRY=30
fi

# Add the column labels to the output file
echo "Host,Port,Lookup,Port Test,Common Name,LDAPv3 DN,Dates,End Date,Days To Expiration,CA Chain,SANs,Issuer,Signature Algorithm,Serial Number,CRL Url,CA Chain Validation,OCSP Check,CRL Status,Layer 7 Check" >$OUTPUT

# Initialize Internal Field Separator
OLDIFS=$IFS
IFS=,

# Line counter for input file errors
line=0

while read host port
  do
  # Increment here
  lineNo=$(($lineNo+1))
  # Sanitize input
  if [[ -z $host ]]
    then
      echo -e "\033[1;31mError: Host is null on line: \033[0m$lineNo\n"
      exit 1
  fi

  if [[ "$host" == *[@#$%'&'*=]* ]]
    then
      echo -e "\033[1;31mError: $host has special characters on line: \033[0m$lineNo\n"
      exit 1
  fi

  if [[ -z $port ]]
    then
      echo -e "\033[1;31mError: Port is null for $host on line: \033[0m$lineNo\n"
      exit 1
  fi

  if [[ ! "$port" =~ ^[[:digit:]]+$ ]]
    then
      echo -e "\033[1;31mError: $port for $host isn't numerical on line: \033[0m$lineNo\n"
      exit 1
  fi

  echo -e "$host"
  echo -e "---------------------------------------"

  # NSLookup
  ## Try both forward and reverse because IPv6, User should validate input values
  ## and the port connection test is the deal/loop breaker
  ## Not recommeded for IP Address entries because lack of consitent PTR management
  ## by many entities for various reasons

  if [[ ! -z $LOOKUP ]]
    then
    ## Try forward first
    lookupTest=$((nslookup $host | awk '/^Address: / { print $2 ; exit }')< /dev/null 2>&1)

    ## If not hostname, try reverse
    if [ -z "$lookupTest" ]
      then
        lookupTest=$((nslookup $host | awk '/\tname = / { print $4 ; exit }' | sed s/.$//)< /dev/null 2>&1)
        if [ -z "$lookupTest" ]
          then
            lookupTest="Failed"
            echo -e "   Lookup: \033[1;31m$lookupTest\033[0m"
          else
            echo -e "   Lookup: \033[1;32m$lookupTest\033[0m"
        fi
    fi
    else
      lookupTest="Skipped"
      echo -e "   Lookup: \033[1;33m$lookupTest\033[0m"
  fi

  # Port connectivity test
  ## If this fails skip all other checks
  portTest=$(($timeoutCommand 2 bash -c "</dev/tcp/$host/$port"; echo $?)< /dev/null 2>&1)
  if [ "$portTest" = 0 ]
    then
      portTest="Open"
      echo -e "   Port $port: \033[1;32m$portTest\033[0m"
    else
      # If failed, set status and skip all other tests
      portTest="Closed"
      echo -e "   Port $port: \033[1;31mClosed\033[0m"
      cn="Skipped"
      ldapDN="Skipped"
      dates="Skipped"
      endDate="Skipped"
      daysToExpiry="Skipped"
      caChain="Skipped"
      san="Skipped"
      issuer="Skipped"
      signature="Skipped"
      serial="Skipped"
      crl="Skipped"
      caValidation="Skipped"
      ocspStatus="Skipped"
      crlValidation="Skipped"
      layer7="Skipped"
      echo -e "   CN: \033[1;33m$cn\033[0m"
      echo -e "   LDAPv3 DN: \033[1;33m$ldapDN\033[0m"
      echo -e "   Dates: \033[1;33m$dates\033[0m"
      echo -e "   End Date: \033[1;33m$endDate\033[0m"
      echo -e "   Days to Expiration: \033[1;33m$daysToExpiry\033[0m"
      echo -e "   CA Chain: \033[1;33m$caChain\033[0m"
      echo -e "   SANs: \033[1;33m$san\033[0m"
      echo -e "   Issuer: \033[1;33m$issuer\033[0m"
      echo -e "   Signature: \033[1;33m$signature\033[0m"
      echo -e "   Serial: \033[1;33m$serial\033[0m"
      echo -e "   CRL: \033[1;33m$crl\033[0m"
      echo -e "   CA Chain Validation: \033[1;33m$caValidation\033[0m"
      echo -e "   OCSP Check: \033[1;33m$ocspStatus\033[0m"
      echo -e "   CRL Check: \033[1;33m$crlValidation\033[0m"
      echo -e "   Layer 7: \033[1;33m$layer7\033[0m"
      echo -e "---------------------------------------"
      echo "$host,$port,$lookupTest,$portTest,$cn,$ldapDN,$dates,$endDate,$daysToExpiry,$caChain,$san,$issuer,$signature,$serial,$crl,$caValidation,$ocspStatus,$crlValidation,$layer7">>$OUTPUT
      continue
  fi

  # Common Name
  if [ ! -z $SPEED ]
    then
      ## Get all the certs
      openssl s_client -showcerts -servername $host -connect $host:$port < /dev/null 2>&1 | awk '/BEGIN /,/END /{ if(/BEGIN/){a++}; out="'"$tempDir/$host"'"a".pem"; print >out}'
      if [ -f $tempDir/${host}1.pem ]
        then
          cn=$(openssl x509 -noout -subject -in $tempDir/${host}1.pem |  grep -m1 "CN" | sed 's/.*CN\(.*\)$/\1/' | cut -d '=' -f 2 | sed 's/\,.*//' | sed 's/[[:space:]]*//' | cut -d '/' -f 1)
        else
          cn="Expecting: TRUSTED"
      fi
    else
      cn=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -subject | grep -m1 "CN" | sed 's/.*CN\(.*\)$/\1/' | cut -d '=' -f 2 | sed 's/\,.*//' | sed 's/[[:space:]]*//' | cut -d '/' -f 1 )< /dev/null 2>&1)
  fi
  if [[ "$cn" =~ "Expecting: TRUSTED" ]]
    then
      cn="Failed"
      echo -e "   CN: \033[1;31m$cn\033[0m"
      dates="Skipped"
      endDate="Skipped"
      daysToExpiry="Skipped"
      caChain="Skipped"
      san="Skipped"
      issuer="Skipped"
      signature="Skipped"
      serial="Skipped"
      crl="Skipped"
      caValidation="Skipped"
      ocspStatus="Skipped"
      crlValidation="Skipped"
      layer7="Skipped"
      echo -e "   Dates: \033[1;33m$dates\033[0m"
      echo -e "   End Date: \033[1;33m$endDate\033[0m"
      echo -e "   Days to Expiration: \033[1;33m$daysToExpiry\033[0m"
      echo -e "   CA Chain: \033[1;33m$caChain\033[0m"
      echo -e "   SANs: \033[1;33m$san\033[0m"
      echo -e "   Issuer: \033[1;33m$issuer\033[0m"
      echo -e "   Signature: \033[1;33m$signature\033[0m"
      echo -e "   Serial: \033[1;33m$serial\033[0m"
      echo -e "   CRL: \033[1;33m$crl\033[0m"
      echo -e "   CA Chain Validation: \033[1;33m$caValidation\033[0m"
      echo -e "   OCSP Check: \033[1;33m$ocspStatus\033[0m"
      echo -e "   CRL Check: \033[1;33m$crlValidation\033[0m"
      echo -e "   Layer 7: \033[1;33m$layer7\033[0m"
      echo -e "---------------------------------------"
      echo "$host,$port,$lookupTest,$portTest,$cn,$ldapDN,$dates,$endDate,$daysToExpiry,$caChain,$san,$issuer,$signature,$serial,$crl,$caValidation,$ocspStatus,$crlValidation,$layer7">>$OUTPUT
      continue
    else
      echo -e "   CN: \033[1;32m$cn\033[0m"
  fi

  # Lightweight Directory Access Protocol (v3):
  # UTF-8 String Representation of Distinguished Names
  # https://tools.ietf.org/html/rfc2253
  # Required for LDAP connection & DN mutual authentication
  if [ ! -z $SPEED ]
    then
      ldapDN=$(openssl x509 -noout -nameopt RFC2253 -subject -in $tempDir/${host}1.pem | sed 's/^.*subject*=\(.*\)$/\1/')
    else
      ldapDN=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -nameopt RFC2253 -subject | sed 's/^.*subject*=\(.*\)$/\1/')< /dev/null 2>&1)
  fi
  if [[ "$ldapDN" =~ "Expecting: TRUSTED" ]];
    then
      ldapDN="Failed"
      echo -e "   LDAPv3 DN: \033[1;31m$ldapDN\033[0m"
    else
      echo -e "   LDAPv3 DN: \033[1;32m$ldapDN\033[0m"
  fi
  # No real CSV spec, see https://www.csvreader.com/csv_format.php
  # Uncomment and Comment or experiment as needed
  ## Escape the commas for Linux
  ## ldapDN=\\"$ldapDN\\"
  ## Escape the commas for Excel
  ldapDN=\"$ldapDN\"

  # Certificate dates
  if [ ! -z $SPEED ]
    then
      dates=$(openssl x509 -noout -dates -in $tempDir/${host}1.pem | cut -d '=' -f 2)
    else
      dates=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -dates | cut -d '=' -f 2)< /dev/null 2>&1)
  fi
  if [[ "$dates" =~ "Expecting: TRUSTED" ]];
    then
      dates="Failed"
      echo -e "   Dates: \033[1;31m$dates\033[0m"
    else
      dates="$(echo "$dates"|tr '\n' '-'|sed s/.$//|sed s/\-/\ \-\ /)"
      echo -e "   Dates: \033[1;32m$dates\033[0m"
  fi

  # End Date
  if [ ! -z $SPEED ]
    then
      endDate=$(openssl x509 -noout -enddate -in $tempDir/${host}1.pem | cut -d '=' -f 2)
    else
      endDate=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -enddate | cut -d '=' -f 2)< /dev/null 2>&1)
  fi
  if [[ "$endDate" =~ "Expecting: TRUSTED" ]];
    then
      endDate="Failed"
      echo -e "   End Date: \033[1;31m$endDate\033[0m"
    else
      echo -e "   End Date: \033[1;32m$endDate\033[0m"
  fi

  # Days to expiration
  expireDate=$($dateCommand '+%s' -d "$endDate")
  currentDate=$($dateCommand +%s)
  daysToExpiry=$(echo $((((( expireDate-currentDate) > 0 ? (expireDate-currentDate) : (currentDate-expireDate)) + 43200) / 86400 )))

  # If the certificate expired days ago
  if [ "$expireDate" -lt "$currentDate" ]
    then
      daysToExpiry=$(($daysToExpiry * -1))
  fi

  # Color text depending on expiry variable
  # or if the certicate is expired
  if [[ "$daysToExpiry" -gt "$EXPIRY" ]]
    then
      echo -e "   Days to Expiration: \033[1;32m$daysToExpiry days\033[0m"
    elif [[ "$daysToExpiry" -le "$EXPIRY" && "$daysToExpiry" -gt 0 ]]
      then
        echo -e "   Days to Expiration: \033[1;33m$daysToExpiry days\033[0m"
      else
        # Remove negative sign
        daysToExpiry=$(echo "$daysToExpiry"| sed s/\-//)
        # Get the grammar correct
        if [[ "$daysToExpiry" -eq 1 ]]
          then
            daysToExpiry=$(echo "Expired $daysToExpiry day ago")
            echo -e "   Days to Expiration: \033[1;31m$daysToExpiry\033[0m"
          else
            daysToExpiry=$(echo "Expired $daysToExpiry days ago")
            echo -e "   Days to Expiration: \033[1;31m$daysToExpiry\033[0m"
        fi
  fi

  # CA Chain
  if [ ! -z $SPEED ]
    then
      certCount=$(ls $tempDir | grep "$host[1-9].pem" -c)
      caCount=2
      caChain=""
      comma=","

      while [[ "$caCount" -le "$certCount" ]]
        do
          caSubject=$(openssl x509 -noout -subject -in $tempDir/${host}${caCount}.pem | sed 's/^.*CN.*=\(.*\)$/\1/' | sed 's/[[:space:]]*//')
          if [[ "$caCount" -eq 2 ]]
            then
              caChain=${caSubject}
          # Append the CAs correctly
          elif [[ "$caCount" -gt 2 ]] && [[ "$caCount" -le "$certCount" ]]
                then
                  caChain=${caChain}${comma}${caSubject}
                else
                  caChain=${caChain}${caSubject}
          fi
          # Increment here
          caCount=$(($caCount+1))
      done
    else
      caChain=$((echo -e "Q\n" | openssl s_client -showcerts -servername $host -connect $host:$port < /dev/null 2>&1 | awk 'BEGIN { x509 = "openssl x509 -noout -subject" } /-----BEGIN CERTIFICATE-----/ { a = "" } { a = a $0 RS } /-----END CERTIFICATE-----/ { print a | x509; close(x509) }' | sed 's/^.*CN.*=\(.*\)$/\1/' | sed '[[:space:]]*')< /dev/null 2>&1)
  fi
  if [[ "$caChain" =~ "Expecting: TRUSTED" ]];
    then
      caChain="Failed"
      echo -e "   CA Chain: \033[1;31m$caChain\033[0m"
    else
    # Ugly parsing hacks. Can and will do better
    if [ -z $SPEED ]
      then
        caChain="$(echo "$caChain" | awk 'NR==1,/(.*)/{sub(/(.*)/, "")}'1)"
    fi
    caChain="$(echo "$caChain" | tr '\n' ',' | sed 's/,/,\[[:space:]]/g')"
    echo -e "   CA Chain: \033[1;32m$caChain\033[0m"

    # No real CSV spec, see https://www.csvreader.com/csv_format.php
    # Uncomment and Comment or experiment as needed
    ## Escape the commas for Linux
    ## ldapDN=\\"$caChain\\"
    ## Escape the commas for Excel
    caChain=\"$caChain\"
  fi

  # SANs
  if [ ! -z $SPEED ]
    then
      san=$(openssl x509 -noout -text -in $tempDir/${host}1.pem | grep -i DNS | sed 's/^[[:space:]]*//')
    else
      san=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -text | grep -i DNS | sed "s/^[[:space:]]*//")< /dev/null 2>&1)
  fi
  if [[ "$san" =~ "Expecting: TRUSTED" ]];
    then
      san="Failed"
      echo -e "   SANs: \033[1;31m$san\033[0m"
    else
      echo -e "   SANs: \033[1;32m$san\033[0m"

      # No real CSV spec, see https://www.csvreader.com/csv_format.php
      # Uncomment and Comment or experiment as needed
      ## Escape the commas for Linux
      ## ldapDN=\\"$san\\"
      ## Escape the commas for Excel
      san=\"$san\"
  fi

  # Issuer
  if [ ! -z $SPEED ]
    then
      issuer=$(openssl x509 -noout -issuer -in $tempDir/${host}1.pem | sed 's/^.*CN.*=\(.*\)$/\1/' | sed 's/[[:space:]]*//')
    else
      issuer=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -issuer | sed 's/^.*CN.*=\(.*\)$/\1/')< /dev/null 2>&1)
  fi
  if [[ "$issuer" =~ "Expecting: TRUSTED" ]];
    then
      issuer="Failed"
      echo -e "   Issuer: \033[1;31m$issuer\033[0m"
    else
      echo -e "   Issuer: \033[1;32m$issuer\033[0m"
  fi

  # Signature Algorithm
  if [ ! -z $SPEED ]
    then
      signature=$(openssl x509 -noout -text -in $tempDir/${host}1.pem | grep -m1 "Signature Algorithm: "| sed 's/^.*rithm:\ \(.*\)$/\1/')
    else
      signature=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -text | grep -m1 "Signature Algorithm: "| sed 's/^.*rithm:\ \(.*\)$/\1/') < /dev/null 2>&1)
  fi
  if [[ "$signature" =~ "Expecting: TRUSTED" ]];
    then
      signature="Failed"
      echo -e "   Signature: \033[1;31m$signature\033[0m"
    else

      # Flag SHA1
      if [[ "$signature" =~ "sha1W" ]];
        then
          echo -e "   Signature: \033[1;33m$signature\033[0m"
        else
          echo -e "   Signature: \033[1;32m$signature\033[0m"
      fi
  fi

  # Serial
  if [ ! -z $SPEED ]
    then
      serial=$(openssl x509 -noout -serial -in $tempDir/${host}1.pem | cut -d '=' -f 2)
    else
      serial=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -serial | cut -d '=' -f 2)< /dev/null 2>&1)
  fi
  if [[ "$serial" =~ "Expecting: TRUSTED" ]];
    then
      serial="Failed"
      echo -e "   Serial: \033[1;31m$serial\033[0m"
    else
      echo -e "   Serial: \033[1;32m$serial\033[0m"
  fi

  # CRL
  if [ ! -z $SPEED ]
    then
      crl=$(openssl x509 -noout -text -in $tempDir/${host}1.pem | grep -A 4 'X509v3 CRL Distribution Points' | grep -m1 "URI:" | sed 's/^.*URI:\(.*\)$/\1/')
    else
      crl=$((echo -e "Q\n" | openssl s_client -servername $host -connect $host:$port < /dev/null 2>&1 | openssl x509 -noout -text | grep -A 4 'X509v3 CRL Distribution Points' | grep -m1 "URI:" | sed 's/^.*URI:\(.*\)$/\1/')< /dev/null 2>&1)
  fi
  if [[ "$serial" =~ "Expecting: TRUSTED" ]];
    then
      crl="Failed"
      echo -e "   CRL: \033[1;31m$crl\033[0m"
    else
      echo -e "   CRL: \033[1;32m$crl\033[0m"
  fi

  # CA Chain Validation
  if [[ $caChain != "Failure" ]] && [[ ! -z $CACHECK ]]
    then
      if [ -z $SPEED ]
        then
          ## Get all the certs
          openssl s_client -showcerts -servername $host -connect $host:$port < /dev/null 2>&1 | awk '/BEGIN /,/END /{ if(/BEGIN/){a++}; out="'"$tempDir/$host"'"a".pem"; print >out}'
      fi
      certCount=$(ls $tempDir | grep "$host[1-9].pem" -c)
      rootCA=${host}${certCount}.pem
      intCA=${host}2.pem
      server=${host}1.pem

      # If only got Intermediate CA
      if [[ "$certCount" -eq 2 ]]
        then
          caValidation=$((openssl verify -untrusted $tempDir/$intCA -purpose sslserver $tempDir/$server)< /dev/null 2>&1)
        else
          # If more than Intermediate, built a CA Chain
          counter=2
          while [[ "$counter" -lt "$certCount" ]]
            do
              # Increment here
              counter=$(($counter+1))
              cat $tempDir/${host}${counter}.pem >> $tempDir/${host}-ca.pem
            done
          caValidation=$((openssl verify -CAfile $tempDir/${host}-ca.pem -untrusted $tempDir/$intCA -purpose sslserver $tempDir/$server)< /dev/null 2>&1)
      fi

      if [[ "$caValidation" =~ "error" ]];
        then
          caValidation="Failed"
          echo -e "   CA Chain Validation: \033[1;31m$caValidation\033[0m"
        else
          caValidation="Success"
          echo -e "   CA Chain Validation: \033[1;32m$caValidation\033[0m"
      fi
    else
      caValidation="Skipped"
      echo -e "   CA Chain Validation: \033[1;33m$caValidation\033[0m"
  fi

  # OCSP Check
  if [[ $caChain != "Failure" ]] && [[ ! -z $OCSPCHECK ]]
    then
      # Get OCSP URI
      if [ -z $SPEED ]
        then
          openssl s_client -showcerts -servername $host -connect $host:$port < /dev/null 2>&1 | awk '/BEGIN /,/END /{ if(/BEGIN/){a++}; out="'"$tempDir/$host"'"a".pem"; print >out}'
      fi
      ocspURI=$((openssl x509 -noout -ocsp_uri -in $tempDir/${host}1.pem)< /dev/null 2>&1)
      if [ ! -z "$ocspURI" ]
        then
        ocspHost=$(echo "$ocspURI" | awk -F/ '{print $3}' )
        ocspStatus=$((openssl ocsp -issuer $tempDir/${host}2.pem -cert $tempDir/${host}1.pem -url $ocspURI -header HOST=$ocspHost < /dev/null 2>&1  | grep -m1 "pem:" | sed 's/.*pem:\(.*\)$/\1/' | cut -d ' ' -f 2) < /dev/null 2>&1)
      else
        ocspStatus="OCSP URI Not found"
      fi
      if [ "$ocspStatus" == "good" ]
        then
          # Capitalize first letter
          ocspStatus=$(echo $ocspStatus | sed 's/g/G/')
          echo -e "   OCSP Check: \033[1;32m$ocspStatus\033[0m"
        elif [[ "$ocspStatus" == "revoked" ]]
          then
            # Capitalize first letter
            ocspStatus=$(echo $ocspStatus | sed 's/r/R/')
            echo -e "   OCSP Check: \033[1;31m$ocspStatus\033[0m"
          else
            echo -e "   OCSP Check: \033[1;33m$ocspStatus\033[0m"
      fi
    else
      ocspStatus="Skipped"
      echo -e "   OCSP Check: \033[1;33m$ocspStatus\033[0m"
  fi

  # CRL Revocation Check
  if [[ $crl != "Failure" ]] && [[ ! -z $CRLCHECK ]]
    then
      curl -s -k $crl --output $tempDir/$host.der < /dev/null 2>&1
      if [ -f $tempDir/$host.der ]
        then
          # Determine CRL format and check
          derTest=$(grep BEGIN $tempDir/$host.der)
          if [ -z $derTest ]
            then
              crlStatus=$(openssl crl -inform DER -text -in $tempDir/$host.der | grep $serial)
            else
              crlStatus=$(openssl crl -inform PEM -text -in $tempDir/$host.der | grep $serial)
          fi
          if [ -z $crlStatus ]
            then
              crlValidation="OK"
              echo -e "   CRL Check: \033[1;32m$crlValidation\033[0m"
            else
              crlValidation="Revoked"
              echo -e "   CRL Check: \033[1;31m$crlValidation\033[0m"
          fi
      else
          crlValidation="Download failed"
          echo -e "   CRL Check: \033[1;33m$crlValidation\033[0m"
      fi
    else
        crlValidation="Skipped"
        echo -e "   CRL Check: \033[1;33m$crlValidation\033[0m"
  fi

  # Layer 7 Head Check
  if [[ ! -z $LAYER7 ]]
    then
      layer7=$((curl -s -k -I --connect-time 5 https://$host:$port/)< /dev/null 2>&1)
      if [[ "$layer7" =~ "curl: (" ]];
        then
          # Continue  with the rest of the certificate tests
          layer7="Failed"
          echo -e "   Layer 7: \033[1;31m$layer7\033[0m"
        else
          layer7="Success"
          echo -e "   Layer 7: \033[1;32m$layer7\033[0m"
      fi
    else
      layer7="Skipped"
      echo -e "   Layer 7: \033[1;33m$layer7\033[0m"
  fi

echo -e "---------------------------------------"

echo "$host,$port,$lookupTest,$portTest,$cn,$ldapDN,$dates,$endDate,$daysToExpiry,$caChain,$san,$issuer,$signature,$serial,$crl,$caValidation,$ocspStatus,$crlValidation,$layer7">>$OUTPUT
done < $INPUT

# If Purge
if [[ ! -z "$PURGE" ]]
  then
    rm -f $tempDir/*.*
fi
IFS=$OLDIFS
