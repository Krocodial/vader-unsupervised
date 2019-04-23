#!/usr/bin/python3

import bat
from virus_total_apis import PublicApi as VT
from bat import log_to_dataframe, dataframe_to_matrix
import pandas as pd
import numpy as np
import sklearn
import csv
import time

df = log_to_dataframe.LogToDataFrame('bro/mixed_traffic/http.log')

df = df['host']
uris = df.values.tolist()
uris = list(set(uris))
print(uris)
vt = VT('')
writer = csv.writer(open('ip_mapping.csv', 'w+'))
error_file = open('errors.txt', 'a+')

def lookup(uri):
	response = vt.get_url_report(uri)
	if 'results' not in response:
		time.sleep(60)
	print(uri)
	print(response['results']['positives'])
	writer.writerow([uri, response['results']['positives']])

for uri in uris:
	try:
		lookup(uri)
	except KeyError:
		error_file.write(uri + '\n')

error_file.close()


