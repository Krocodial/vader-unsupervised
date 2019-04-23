#!/usr/bin/python3

import bat
import csv
from virus_total_apis import PublicApi as VT
from bat import log_to_dataframe, dataframe_to_matrix
import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
import tkinter
from geoip import geolite2

clean_df = log_to_dataframe.LogToDataFrame('bro/clean_traffic/http.log')
mixed_df = log_to_dataframe.LogToDataFrame('bro/mixed_traffic/http.log')

print(clean_df.head())
print(mixed_df.head())
#trans_depth
features = ['ts', 'day', 'id.resp_h', 'id.resp_p', 'method', 'host', 'user_agent', 'request_body_len', 'response_body_len', 'status_code', 'info_code']
#features = ['id.orig_h', 'id.resp_h']

clean_df = clean_df.reset_index()
mixed_df = mixed_df.reset_index()

#clean_df = clean_df[clean_df.service != 'dns']
#mixed_df = mixed_df[mixed_df.service != 'dns']

def convert(ip):
	match = geolite2.lookup(ip)
	if match is None:
		return 'N/a'
	if match.country is None:
		return 'N/a'
	return match.country

clean_df['id.resp_h'] = clean_df['id.resp_h'].apply(convert)
mixed_df['id.resp_h'] = mixed_df['id.resp_h'].apply(convert)

clean_df = clean_df[clean_df['id.resp_h'] != 'N/a']
mixed_df = mixed_df[mixed_df['id.resp_h'] != 'N/a']

def minutes(ts):
	hour = ts.hour
	minu = ts.minute
	return hour*60 + minu

clean_df['day'] = clean_df['ts'].apply(lambda x: x.dayofweek)
mixed_df['day'] = mixed_df['ts'].apply(lambda x: x.dayofweek)

clean_df['ts'] = clean_df['ts'].apply(minutes)
mixed_df['ts'] = mixed_df['ts'].apply(minutes)

orig_df = mixed_df

clean_df = clean_df[features]
mixed_df = mixed_df[features]
clean_df['label'] = 'train'
mixed_df['label'] = 'score'

print(clean_df.head())
print(mixed_df.head())

#clean_df = clean_df.reset_index(drop=True)
#mixed_df = mixed_df.reset_index(drop=True)


for col in clean_df:
	clean_df['id.resp_p'] = clean_df['id.resp_p'].astype('category')
	clean_df['id.resp_h'] = clean_df['id.resp_h'].astype('category')

for col in mixed_df:
	mixed_df['id.resp_p'] = mixed_df['id.resp_p'].astype('category')
	mixed_df['id.resp_h'] = mixed_df['id.resp_h'].astype('category')

print(clean_df.dtypes)

clean_df.to_csv('clean_output.csv')
mixed_df.to_csv('mixed_output.csv')


concat_df = pd.concat([clean_df, mixed_df])
#features_df = pd.get_dummies(concat_df, columns=['id.resp_h', 'id.resp_p', 'proto', 'service', 'orig_bytes', 'resp_bytes'], dummy_na=True)

features_df = pd.get_dummies(concat_df, columns=['id.resp_h', 'id.resp_p', 'method', 'host', 'user_agent', 'status_code', 'info_code'])
features_df.to_csv('concatted_output.csv')

train_df = features_df[features_df['label'] == 'train']
score_df = features_df[features_df['label'] == 'score']

train_df = train_df.drop('label', axis=1)
score_df = score_df.drop('label', axis=1)

#bro_df[features].to_csv('output.csv')
#train_df.to_csv('clean_output.csv')
#score_df.to_csv('mixed_output.csv')

clean_matrix = train_df.to_numpy()
mixed_matrix = score_df.to_numpy()



def isolationFor(clean_matrix, mixed_matrix, percents):
	uniq_uris = []
	for percent in percents:
		model = IsolationForest(contamination=percent).fit(clean_matrix)
		#results = mixed_df[features][model.predict(mixed_matrix) == -1]
		results = orig_df[model.predict(mixed_matrix) == -1]
		name = 'isolation_' + str(percent)
		results.to_csv('output/' + name + '_outliers.csv')
		parseResults(results, name)

		#uris = []
		#df = results['host']
		#uris = df.values.tolist()
		#uniq_uris = uniq_uris + uris
		#print(list(set(uniq_uris)))

def robustCovariance():
	pass

def oneClassSVM():
	pass

def localOutlierFactor():
	pass
	#https://scikit-learn.org/stable/modules/outlier_detection.html

def parseResults(results, name):
	df = results['host']
	uris = df.values.tolist()
	uniq = list(set(uris))	
	writer =  csv.writer(open('output/' + name + '.csv', 'w+'))
	vt = VT('2c90cbca5025f72aa9fcf5275ae91198c4929fd34a7dd5b80ff4c2aeaeef6f54')
	for uri in uniq:
		response = vt.get_url_report(uri)
		if 'results' not in response:
			print(response, uri)
		print(response['results']['positives'])
		writer.writerow([uri, response['results']['positives']])
	
percents = [.01, .05, .10]
isolationFor(clean_matrix, mixed_matrix, percents)



