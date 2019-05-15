# VirusTotal Submitter Information Maltego Transform

## Introduction
This Maltego Transform accepts a hash and extracts basic, useful information about a VirusTotal submitter of a specific Hash.
Born out of need. I haven't come across such transfrom, nor the ability to create one before VirusTotal private API v3. 
The .mtz also contains one Entity which translates the submitter's country code to its flag using Maltego 4.2 entity overlays.

## Prerequisites
- VirusTotal Private API Access
- Python 2.7.X, requests, json 
- Maltego 4.2.X

## Example
![Alt text](/Screenshot.png?raw=true)

## Setup
With the prerequisites met, clone repository to a local folder.

1. Edit VTSubmitter.py and insert your VirusTotal private API key.
2. Import VTSubmitter.mtz to Maltego, making sure to import both the transform and the entity.
3. Go to Transforms -> Transform Manager -> VTSubmitter and set:
  - Command line: C:\Python27\python.exe (or your python.exe folder)
  - Working directory: The folder where you cloned this repository to.
  - Uncheck "Show debug info"

## Known issues
If multiple countries per submitter ID exists, the transform will choose the first country it gets.

### P.S.
You can easily edit the transform so it'll create also a 'Country' entity. I haven't found it to be useful for me. Just add:
```
me = mt.addEntity("maltego.Country", '%s' % item['attributes']['country'].encode("ascii"))
```
after ```if 'country' in item['attributes']:```
