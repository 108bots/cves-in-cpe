import requests
import argparse
import json

"""
    cves_in_cpe: Get a list of CVEs for a given CPE by looking up NVD APIs documented at https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CPE%20Retrieval.pdf
    Returns below structure as json string or file:
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
"""

def get_cve(cve_id):
    """
    Query CVE from NVD for a given ID
    Returns: CVE detail as dictionary keyed by CVE ID
    {
        cve : {
                    'title': string,
                    'cvss_version': string
                    'cvssv_base_score': number,
                    'cvssv_base_severity': string,
                    'cwes': [string, string]
        }
    }
    """

    if not cve_id:
        return {}

    cve_id = cve_id.upper()
    
    # simple check on CVE format
    if not cve_id.startswith('CVE-'):
        return ()

    # Call NVD API to query CVE
    nvd_cve_URL = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + cve_id
    headers = requests.utils.default_headers()
    req = requests.get(nvd_cve_URL, headers=headers)
    print ('Querying NVD for: '+cve_id)
    if req.status_code != 200:
        return {'error': cve_id+' API response error. Code: '+str(req.status_code)}
        
    cve_response = req.json()
    cve_details = {}

    try:
        title = cve_response['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
        impact = cve_response['result']['CVE_Items'][0]['impact']
        # handle cvss v3 and v2
        cvss_version = ''
        if 'baseMetricV3' in impact.keys():
            cvss_version = 'V3'
        elif 'baseMetricV2' in impact.keys():
            cvss_version = 'V2'
        
        if cvss_version == 'V3':
            cvss_base_score = impact['baseMetricV3']['cvssV3']['baseScore']
            cvss_base_severity = impact['baseMetricV3']['cvssV3']['baseSeverity']
        if cvss_version == 'V2':
            cvss_base_score = impact['baseMetricV2']['cvssV2']['baseScore']
            cvss_base_severity = impact['baseMetricV2']['severity']
        # collect CWEs if present
        cwes = []
        for cwe in cve_response['result']['CVE_Items'][0]['cve']['problemtype']['problemtype_data'][0]['description']:
            cwe = cwe['value'].upper()
            if cwe.startswith('CWE-'):
                cwes.append(cwe)

        cve_details['title'] = title
        cve_details['cvss_version'] = cvss_version
        cve_details['cvss_base_score'] = cvss_base_score
        cve_details['cvss_base_severity'] = cvss_base_severity.upper()
        cve_details['cwes'] = cwes
        
    except KeyError as exp:
        return {'error': 'Key not found in '+cve_id+' API Response:'+str(exp)}
        

    return {cve_id:cve_details}


def get_cpe_cves(**kwargs):
    """
    Query CVEs from NVD for a given CPE
    Returns: Dictionary of results in below format
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
    """
    
    if kwargs is None:
        return {'error':'no data passed'}
    
    kwargs = dict((k.lower(), v.lower()) for k, v in kwargs.items())

    if 'product' not in kwargs.keys():
        return {'error':'product name is required'}

    if 'part' not in kwargs.keys():
        kwargs['part'] = 'a'
    if 'vendor' not in kwargs.keys():
        kwargs['vendor'] = '*'
    if 'version' not in kwargs.keys():
        kwargs['version'] = '*'
    if 'update' not in kwargs.keys():
        kwargs['update'] = '*'
    if 'language' not in kwargs.keys():
        kwargs['language'] = '*'
    if 'sw_edition' not in kwargs.keys():
        kwargs['sw_edition'] = '*'
    if 'target_sw' not in kwargs.keys():
        kwargs['target_sw'] = '*'
    if 'target_hw' not in kwargs.keys():
        kwargs['target_hw'] = '*'
    if 'other' not in kwargs.keys():
        kwargs['other'] = '*'
        
    nvd_cpe_baseURL = 'https://services.nvd.nist.gov/rest/json/cpes/1.0'
    cpe_ver = '2.3'
    cpe_match_string = 'cpe:'+cpe_ver+':'+kwargs['part']+':'+kwargs['vendor']+':'+kwargs['product']+':'+kwargs['version']+':'+kwargs['update']+':'+kwargs['language']+':'+kwargs['sw_edition']+':'+kwargs['sw_edition']+':'+kwargs['target_sw']+':'+kwargs['target_hw']+':'+kwargs['other']
    
    cpe_cve_results = {
        'cpe_match_string': cpe_match_string, 
        'cpe_count': 0, 
        'cve_count': 0, 
        'cpes': []
    }

    # set resultsPerPage to the maximum allowed of 5000
    max_results_per_page = 5000
    start_index = 0
    records_pending = 1
    cpe_count = 0

    headers = requests.utils.default_headers()
    while records_pending > 0:
        # Call NVD API to query CPE
        payload = {'cpeMatchString': cpe_match_string, 'startIndex': start_index, 'resultsPerPage': max_results_per_page, 'addOns': 'cves'}
        req = requests.get(nvd_cpe_baseURL, params=payload, headers=headers)

        if req.status_code != 200:
            return {'error': 'StartIndex: '+str(start_index)+' CPE API response error. Code: '+str(req.status_code)}
        
        cpe_response = req.json()

        try:
            cpe_count = cpe_response['result']['cpeCount']
            cpe_cve_results['cpe_count'] = cpe_count 
            print ('\nFound '+str(cpe_count)+' CPEs...\n')
            ctr = 0
            for cpe in cpe_response['result']['cpes']:
                
                print ('\n['+str(ctr)+']Enumerating: '+cpe['cpe23Uri']+'... Found '+str(len(cpe['vulnerabilities']))+' CVEs\n')
                cpe_cve_results['cpes'].append({'cpe_uri': cpe['cpe23Uri'], 'vulns': {}})
                # get details for each CVE and add to vulns
                for cve in cpe['vulnerabilities']:
                    print ('Looking up: '+cve)
                    # check if cve was already queried before, if so, copy details and avoid API call 
                    cve_details = {}
                    for c in cpe_cve_results['cpes']:
                        if cve in c['vulns'].keys():
                            cve_details[cve.upper()] = c['vulns'][cve]
                            print ('Found it locally!!')
                            break            
                    # Query CVE from NVD
                    if not cve_details:
                        cve_details = get_cve(cve)

                    cpe_cve_results['cpes'][ctr]['vulns'].update(cve_details)

                cpe_cve_results['cve_count'] += len(cpe_cve_results['cpes'][ctr]['vulns'])
                ctr+=1
            
        except KeyError as exp:
            return {'error': 'Key not found in CPE API Response:'+str(exp)}
        
        # break if all results are retrieved in single page
        if cpe_count <= max_results_per_page:
            break
        
        # set up for next page retrieval
        start_index += max_results_per_page
        records_pending = cpe_count - start_index
        
    return cpe_cve_results    
    

"""
   Setup and parse arguments
"""
def main():
    parser = argparse.ArgumentParser(description='Get a list of CVEs for a given v2.3 CPE by looking up NVD. See https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf for CPE specifications')
    parser.add_argument('--part', required=False, default='a', help='Part can be one of a, h, or o')
    parser.add_argument('--vendor', required=False, default='*', help='Vendor or manufacturer name. Ex: apache')
    parser.add_argument('--product', required=True, help='Product or package name. Ex: struts')
    parser.add_argument('--version', required=False, default='*', help='Version string. Ex: 1.4.3')
    parser.add_argument('--update', required=False, default='*', help='Update string. Ex: rel1, upd2')
    parser.add_argument('--language', required=False, default='*', help='Language string. Ex: en-us')
    parser.add_argument('--sw_edition', required=False, default='*', help='Software Edition string. Ex: home_premium')
    parser.add_argument('--target_sw', required=False, default='*', help='Target Software string. Ex: foo_bar')
    parser.add_argument('--target_hw', required=False, default='*', help='Target hardware string. Ex: x64')
    parser.add_argument('--other', required=False, default='*', help='Other generic string. Ex: foo_bar')

    args = parser.parse_args()

    if not args.product:
        parser.error('--product is required. See --help.')

    # call get_cpe_cves to get CVEs for a give CPE
    cpe_cves = get_cpe_cves(**vars(args))
    
    # write output
    print ('\n\n***SUMMARY***\n')
    if 'cpe_match_string' in cpe_cves.keys():
        print ('CPE Match string: ', cpe_cves['cpe_match_string'])
    if 'cpe_count' in cpe_cves.keys():
        print ('CPE Count: ', cpe_cves['cpe_count'])
    if 'cve_count' in cpe_cves.keys():
        print ('CVE Count: ', cpe_cves['cve_count'])
    
    with open('cpe_cve_out.json', 'w') as file:
            file.write(json.dumps(cpe_cves))
    print ('\nFurther details: See cpe_cve_out.json\n')

if __name__ == "__main__":
    main()

