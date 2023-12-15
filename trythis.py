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
new_df=[]
start=0
end=3

for j in range(0,10):
  for i in range(10):
    #get the length of each link
    url_length=[]
    for i in range(start,end):
      url_length.append(len(df['url'][i]))
      
    #get the content length
    content_length=[]
    for i in range(start,end):
      link=df['url'][i]
      try:
        content_length.append(urlopen(link).info().get('Content-Length'))
      except:
        content_length.append(-1)
      
    #type section (if malicious type is 1 if not then 0)
    mal=[]
    for i in range(start,end):
      if df['type'][i]=='benign':
        mal.append(0)
      else:
        mal.append(1)
      
    #get charsets
    charsets=[]
    for k in range(start,end):
      try:
        charsets.append(urlopen(df['url'][k]).info().get_charsets())
      except:
        charsets.append(-1)
      
    #get the server names
    server=[]
    for k in range(start,end):
      try:
        f=urlopen(df['url'][k])
        i=f.info()
        server.append(i.get('server'))
      except:
        server.append(-1)
      
    #get the number of special characters in a link
    special=[]
    for i in range(start,end):
      special.append(count_special_characters(df['url'][i]))
      
    #now add back in the original url
    url=[]
    for k in range(start,end):
      url.append(df['url'][k])
    #save the data to a new csv file for further processing
    data={'url':url,'url_length':url_length,'content_length':content_length,'mal':mal,'charsets':charsets,'server':server,'special_chars':special}
    temp_df=pd.DataFrame(data,columns=['url','url_length','content_length','mal','charsets','server','special_chars'],index=list(range(start,end)))
    new_df.append(temp_df)
    start=end
    end+=3
    print(end)
  new_df=pd.concat(new_df)
  new_df.to_csv('File'+str(j)+'.csv')
  new_df=[]

