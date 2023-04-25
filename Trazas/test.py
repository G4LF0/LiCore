import pandas as pd
import csv

with open('Trazas\Trazas.csv', newline='') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=';', quotechar='|')
    for row in spamreader:
        print(', '.join(row))