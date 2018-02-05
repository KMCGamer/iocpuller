**Note:** This is primarily for the University of South Carolina Information Security Team. However, you are free use any code you find useful for your own projects. Understand that this repository is not meant to work for everyone and **will not** be maintained.

### Description

The iocpuller script pulls ioc (indicator of compromise) information from a [Request Tracker](https://bestpractical.com/request-tracker/) server, parses, and writes the information in an [indel.dat](https://www.bro.org/current/solutions/intel/index.html) file. Bro, a network security monitor, will then alert whenever it sees the indicators inside network log files.

To minimize false-positives, a text file of the top one million most popular websites is scanned against the ioc domain to determine if it should be included in the indel.dat file. An additional whitelist file is also available to manually enter in domains that are safe.

### REST

[Request Tracker's REST API](http://rt-wiki.bestpractical.com/wiki/REST) is used to retrieve the ioc data. The query is based on a certain field like `CF.{ioc.domain}` or `CF.{ioc.filehash}` (CF stands for "custom field"). The query checks to make sure the field exists, only searches tickets past a certain id, and makes sure that the status of the request was no `rejected` or `abandoned`.

### Pulling

To start a pull, type `./iocpuller.py pull INTEL_FILE WEBSITES_FILE`. The `INTEL_FILE` is the location of the intel.dat file. The file is by default located in `/opt/bro/share/bro/intel/intel.dat`. `WEBSITES_FILE` is the top websites text file that you must download on your own. *You could use the one in this repository, but it will not be up to date with the latest rankings.* You can use the [Majestic Million](https://majestic.com/reports/majestic-million) to get the updated data.


### Whitelist Manager

The whitelist manger is a command line interface used to easily create, read, update, and remove domains/file hashes/ip addresses from the whitelist text file.

To use the whitelist manager, type `./iocpuller.py whitelist`. This will bring up the CLI. You will be presented with many different options. When you are done editing the whitelist, chose menu option **5** to save and then **7** to exit.


### Important

Make sure the command is ran as root. It will be editing files in normally unaccessible locations to underprivileged users.