################################################################
#  Author     : Sid McLaurin
#  Copyright  : Copyright (c) SID Solutions
#  Date       : 04/01/2019
#  Version    : 0.1
#  License    : GNU General Public License
#  GitHub     : https://github.com/sidsolutions-net/pki-toolkit
#################################################################
#  Description:
# - Remote PKI Validation Script - Windows
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
# - PowerShell commands
#
#   $Id: networkPKIValidation.ps1, v 0.1
#################################################################
