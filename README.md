# cves-in-cpe

Look up Common Vulnerabilities and Exposures (CVEs) for a given product, package etc specified using the Common Platform Enumeration (CPE) from the U.S. National Vulnerability Database (NVD).

# Usage

```
usage: cves_in_cpe.py [-h] [--part PART] [--vendor VENDOR] --product PRODUCT
                      [--version VERSION] [--update UPDATE]
                      [--language LANGUAGE] [--sw_edition SW_EDITION]
                      [--target_sw TARGET_SW] [--target_hw TARGET_HW]
                      [--other OTHER]

Get a list of CVEs for a given v2.3 CPE by looking up NVD. See https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf for CPE specifications

optional arguments:
  -h, --help            show this help message and exit
  --part PART           Part can be one of a, h, or o
  --vendor VENDOR       Vendor or manufacturer name. Ex: apache
  --product PRODUCT     Product or package name. Ex: struts
  --version VERSION     Version string. Ex: 1.4.3
  --update UPDATE       Update string. Ex: rel1, upd2
  --language LANGUAGE   Language string. Ex: en-us
  --sw_edition SW_EDITION
                        Software Edition string. Ex: home_premium
  --target_sw TARGET_SW
                        Target Software string. Ex: foo_bar
  --target_hw TARGET_HW
                        Target hardware string. Ex: x64
  --other OTHER         Other generic string. Ex: foo_bar
```
# Output

Returns below structure as a json string or file:
```
     { 
        'cpe_match_string': string
        'cpe_count': number, 
        'cve_count': number,
        'cpes':[
        {
            'cpe_uri': string, 
            'vulns':
            {
                cve : {
                            'title': string,
                            'cvss_version': string
                            'cvss_base_score': number,
                            'cvss_base_severity': string,
                            'cwes': [string, string]
                      }
            }
        }
        ]
    }
```
# Example

Lookup all Vulnerabilities in 'struts' package: 
* _python cves_in_cpe.py --product struts_

Lookup Vulnerabilities in 'struts' package version 2.5.12: 
* _python cves_in_cpe.py --product struts --version 2.5.12_

Sample output file at ./cpe_cve_out.json

# NVD API Reference

* https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CPE%20Retrieval.pdf
* https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf

