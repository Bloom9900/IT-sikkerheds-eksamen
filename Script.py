import shodan
from shodan.cli.helpers import get_api_key
import argparse
from tabulate import tabulate

api = shodan.Shodan(get_api_key())

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--isp', metavar='\b', type=str, required=True, help='The internet service provider you would like to search for vulnerabilities.')
parser.add_argument('-l', '--limit', metavar='\b', type=int, help='Put a limit on the number of results you want to download from Shodan.')

args = parser.parse_args()

try:
        results = api.search('has_vuln:true country:DK org:'+args.isp, limit=args.limit)

        table = [['Host: '+args.isp, 'Antal Sårbarheder', 'Højeste CVSS']]

        for result in results['matches']:
                highVal = 0.0   
                for vuln in result['vulns']:
                        if(float(result['vulns'][vuln]['cvss']) > highVal):
                                highVal = float(result['vulns'][vuln]['cvss'])

                table.append([result['ip_str'], len(result['vulns']), highVal])

        print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))

except shodan.APIError as e:
        print('Error: {}'.format(e))