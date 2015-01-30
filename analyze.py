import pandas as pd
import numpy as np
import sys
import matplotlib.pyplot as plt
import re
from pandas import Series, DataFrame, Panel
import pylab as pl

def main():
    
    log_file = open('access.log', 'r')

    df = get_log_as_frame(log_file)
    print(df)
    df['Status'] = df['Status'].astype('int')
    print('< < < < < < Done reading frame > > > > > >')

    set_index(df, 'Date')
    print('< < < < < < Done setting index on timestamp > > > > > >')

    df_s = resample_column(df, 'Status', '1Min')
    print('< < < < < < Done resampling requests per minute > > > > >')
    df_s.plot()

    #df_api = get_requests_regex(df, 'api')
    #df_queries = get_requests_regex(df, '\?query')
    #print(df_queries)
    
    grouped_status = df.groupby('Status')
    print('< < < < < < Done grouping by response code > > > > > >')
    fig = pl.figure()
    print(grouped_status.size())
    grouped_status.size().plot(kind='bar')
    pl.show()

def set_index(df, column):
    df.index = pd.to_datetime(df.pop(column).str.replace(":", " ", 1))

def resample_column(df, column, interval):
    df_resampled = df[column].resample(interval, how='count')
    return df_resampled

def get_requests_regex(df, regex):
    df_requests = df['URL'][df['URL'].str.contains(regex)]
    return df_requests

def get_log_as_frame(log_file):
    a = [];

    #line = log_file.readline()
    for line in log_file:
        #line = log_file.readline()
        #p = re.compile('(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST) )(?P<url>.+)(http\/1\.1")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["])')
        p = re.compile('(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] \"(GET|POST) (?P<url>.+) (HTTP\/1\.1") (?P<statuscode>\d{3}) (?P<bytessent>\d+)')
        matches = p.findall(line)
        if matches:
            a.append(matches[0])

    df = DataFrame(a, columns=['IP', 'Date', 'Request method', 'URL', 'Protocol', 'Status', 'Size']);
    return df

if __name__ == "__main__":
    main()
