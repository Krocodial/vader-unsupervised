#!/usr/bin/python3

import bat
from bat import log_to_dataframe, dataframe_to_matrix
import pandas as pd
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
import tkinter
from geoip import geolite2

clean_df = log_to_dataframe.LogToDataFrame('bro/clean_traffic/conn.log')
mixed_df = log_to_dataframe.LogToDataFrame('bro/malicious_traffic/conn.log')
print(clean_df.head())
print(mixed_df.head())
features = ['ts', 'day', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'local_orig', 'local_resp', 'orig_pkts', 'resp_pkts']
#features = ['id.orig_h', 'id.resp_h']

clean_df = clean_df.reset_index()
mixed_df = mixed_df.reset_index()

clean_df = clean_df[clean_df.service != 'dns']
mixed_df = mixed_df[mixed_df.service != 'dns']

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
	clean_df['proto'] = clean_df['proto'].astype('category')
	clean_df['service'] = clean_df['service'].astype('category')
	clean_df['duration'] = clean_df['duration'].astype('int64')

for col in mixed_df:
	mixed_df['id.resp_p'] = mixed_df['id.resp_p'].astype('category')
	mixed_df['id.resp_h'] = mixed_df['id.resp_h'].astype('category')
	mixed_df['proto'] = mixed_df['proto'].astype('category')
	mixed_df['service'] = mixed_df['service'].astype('category')
	mixed_df['duration'] = mixed_df['duration'].astype('int64')

print(clean_df.dtypes)

clean_df.to_csv('clean_output.csv')
mixed_df.to_csv('mixed_output.csv')


concat_df = pd.concat([clean_df, mixed_df])
#features_df = pd.get_dummies(concat_df, columns=['id.resp_h', 'id.resp_p', 'proto', 'service', 'orig_bytes', 'resp_bytes'], dummy_na=True)

features_df = pd.get_dummies(concat_df, columns=['id.resp_h', 'id.resp_p', 'proto', 'service'])
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

#to_matrix = dataframe_to_matrix.DataFrameToMatrix()
#clean_matrix = dataframe_to_matrix.DataFrameToMatrix().transform(train_df)
#mixed_matrix = dataframe_to_matrix.DataFrameToMatrix().transform(score_df)


#results = IsolationForest().fit_predict(mixed_matrix)

model = IsolationForest(contamination=0.10).fit(clean_matrix)
results = mixed_df[features][model.predict(mixed_matrix) == -1]
print(results.shape)
print(results.head())

results.to_csv('outliers.csv')


'''
print(bro_matrix)

print(bro_matrix.shape)

odd_clf = IsolationForest(contamination=0.01)
odd_clf.fit(bro_matrix)
odd_df = bro_df[features][odd_clf.predict(bro_matrix) == -1]
print(odd_df.shape)
print(odd_df.head())

odd_matrix = to_matrix.fit_transform(odd_df)
print(odd_matrix)
'''


'''
kmeans = KMeans(n_clusters=4).fit_predict(odd_matrix)
pca = PCA(n_components=3).fit_transform(odd_matrix)

odd_df['x'] = pca[:, 0]
odd_df['y'] = pca[:, 1]
odd_df['cluster'] = kmeans

import matplotlib.pyplot as plt
plt.rcParams['font.size'] = 14.0
plt.rcParams['figure.figsize'] = 15.0, 6.0

def jitter(arr):
	stdev = .02*(max(arr)-min(arr))
	return arr + np.random.randn(len(arr)) * stdev

odd_df['jx'] = jitter(odd_df['x'])
odd_df['jy'] = jitter(odd_df['y'])

cluster_groups = odd_df.groupby('cluster')
colors = {0:'green', 1:'blue', 2:'red', 3:'orange', 4:'purple', 5:'brown'}
fig, ax = plt.subplots()
for key, group in cluster_groups:
	group.plot(ax=ax, kind='scatter', x='jx', y='jy', alpha=0.5, s=250, label='Cluster: {:d}'.format(key), color=colors[key])
group.show()
'''
#odd_df.to_csv('output.csv')
