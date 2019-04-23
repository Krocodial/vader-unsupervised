#!/usr/bin/python3

import bat
import csv
from virus_total_apis import PublicApi as VT
from bat import log_to_dataframe, dataframe_to_matrix
import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.covariance import EllipticEnvelope
from sklearn.svm import OneClassSVM

from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
import tkinter
from geoip import geolite2

clean_df = log_to_dataframe.LogToDataFrame('bro/clean_traffic/http.log')
mixed_df = log_to_dataframe.LogToDataFrame('bro/mixed_traffic/http.log')

#print(clean_df.head())
#print(mixed_df.head())
#trans_depth
features = ['ts', 'day', 'id.resp_h', 'id.resp_p', 'method', 'host', 'user_agent', 'request_body_len', 'response_body_len', 'status_code', 'info_code']

clean_df = clean_df.reset_index()
mixed_df = mixed_df.reset_index()

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

'''
for col in clean_df:
	clean_df['id.resp_p'] = clean_df['id.resp_p'].astype('category')
	clean_df['id.resp_h'] = clean_df['id.resp_h'].astype('category')

for col in mixed_df:
	mixed_df['id.resp_p'] = mixed_df['id.resp_p'].astype('category')
	mixed_df['id.resp_h'] = mixed_df['id.resp_h'].astype('category')
'''

clean_df.to_csv('clean_output.csv')
mixed_df.to_csv('mixed_output.csv')


concat_df = pd.concat([clean_df, mixed_df])

features_df = pd.get_dummies(concat_df, columns=['id.resp_h', 'id.resp_p', 'method', 'host', 'user_agent', 'status_code', 'info_code'])
features_df.to_csv('concatted_output.csv')

train_df = features_df[features_df['label'] == 'train']
score_df = features_df[features_df['label'] == 'score']

train_df = train_df.drop('label', axis=1)
score_df = score_df.drop('label', axis=1)

clean_matrix = train_df.to_numpy()
mixed_matrix = score_df.to_numpy()

def isolationFor(clean_matrix, mixed_matrix, percents):
	uniq_uris = []
	for percent in percents:
		model = IsolationForest(n_estimators=1000, behaviour='new', max_samples=0.8, contamination=percent).fit(clean_matrix)
		#model = IsolationForest(contamination=percent).fit(clean_matrix)
		#results = mixed_df[features][model.predict(mixed_matrix) == -1]
		results = orig_df[model.predict(mixed_matrix) == -1]
		name = 'isolation_' + str(percent)
		results.to_csv('output/' + name + '_outliers.csv')
		parseResults(results, name)


def robustCovariance(clean_matrix, mixed_matrix, percents):
	for percent in percents:
		model = EllipticEnvelope(contamination=percent).fit(clean_matrix)
		results = orig_df[model.predict(mixed_matrix) == -1]
		name = 'covariance_' + str(percent)
		results.to_csv('output/' + name + '_outliers.csv')
		parseResults(results, name)

def oneClassSVM():
	for percent in percents:
		model = EllipticEnvelope(contamination=percent).fit(clean_matrix)
		results = orig_df[model.predict(mixed_matrix) == -1]
		name = 'covariance_' + str(percent)
		results.to_csv('output/' + name + '_outliers.csv')
		parseResults(results, name)

def localOutlierFactor():
	pass
	#https://scikit-learn.org/stable/modules/outlier_detection.html

def parseResults(results, name):
	mapping = {}
	with open('ip_mapping.csv', newline='') as csvfile:
		reader = csv.reader(csvfile)
		for row in reader:
			mapping[row[0]] = row[1]

	result_hosts = results['host'].tolist()
	total = len(result_hosts)
	mal = 0
	for host in result_hosts:
		if int(mapping[host]) != 0:
			mal = mal + 1
	print('-----' + name + ' results-----')
	print(total)
	print(mal)	
	print('---end---')


percents = [.0, .01, .05, .10, .20]
isolationFor(clean_matrix, mixed_matrix, percents)
robustCovariance(clean_matrix, mixed_matrix, percents)


