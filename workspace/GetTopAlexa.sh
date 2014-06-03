#!/bin/bash          
echo Downloading the most recent TOP Alexa...
wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip

echo Unzipping the archive...
unzip -o top-1m.csv.zip

echo Deleting the archive...
rm top-1m.csv.zip
