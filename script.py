import pandas as pd
import numpy as np
import os
import urllib.request
import requests
os.chdir('C:\\Users\\georg\\OneDrive\\Desktop\\transform')
df=pd.read_csv('malicious_phish.csv')

#get the length of each link
url_length=[]
for i in df['url']:
  url_length.append(len(i))
df['url_length']=url_length
df['url_length']

#get the content length
content_length=[]
count=0
for i in range(1000):
  link=df['url'][i]
  try:
    content_length.append(len(requests.get(link).text))
  except:
    content_length.append(-1)
content_length
  


