def count_special_characters(input_string):
    special_characters = 0
    for char in input_string:
        if not char.isalnum() and not char.isspace():
            special_characters += 1
    return special_characters

import pandas as pd
import numpy as np
import os
import urllib.request
import requests
from urllib.request import urlopen

os.chdir('C:\\Users\\georg\\OneDrive\\Desktop\\transform')
df=pd.read_csv('malicious_phish.csv')
n=1781 #len(df['url'])
df=df.iloc[0:n]
#get the length of each link
url_length=[]
for i in range(n):
  url_length.append(len(df['url'][i]))
df['url_length']=url_length
print('Step 1 of 6 Complete')
#get the content length
content_length=[]
for i in range(n):
  link=df['url'][i]
  try:
    content_length.append(urlopen(link).info().get('Content-Length'))
  except:
    content_length.append(-1)
   
df['content_length']=content_length
print('Step 2 of 6 Complete')

#type section (if malicious type is 1 if not then 0)
mal=[]
for i in range(n):
  if df['type'][i]=='benign':
    mal.append(0)
  else:
    mal.append(1)
df['type']=mal
print('Step 3 of 6 Complete')
#get charsets
charsets=[]
for k in range(n):
  try:
    charsets.append(urlopen(df['url'][k]).info().get_charsets())
  except:
    charsets.append(-1)
df['charsets']=charsets
print('Step 4 of 6 Complete')
#get the server names
server=[]
for k in range(n):
  try:
    f=urlopen(df['url'][k])
    i=f.info()
    server.append(i.get('server'))
  except:
    server.append(-1)
df['server']=server
print('Step 5 of 6 Complete')
#get the number of special characters in a link
special=[]
for i in range(n):
  special.append(count_special_characters(df['url'][i]))
df['special_characters']=special
print('Step 6 0f 6 Complete')

#save the data to a new csv file for further processing
df.to_csv('File.csv')
