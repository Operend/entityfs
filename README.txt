
- This requires pip package fuse-python, NOT fusepy.
  Unfortunately, the two packages are incompatible.
  If you're not virtualizing your Python environments, you might need
  to actually uninstall fusepy before installing fuse-python.
- fuse-python depends on having "libfuse3-dev" on the system, not just "libfuse"
- To configure, either: cp example.ini ~/.entityfs
  OR: cp example.ini WHEREVER; export ENTITYFS_CONFIG=WHEREVER;
  then edit that file as necessary
- To start: entityfs.py [mountpoint] [options]
  The main option is --config FILENAME, to point at a config file
  without using a command line argument.
- To cleanly unmount: fusermount -u [mountpoint]
  In my testing, kill or even kill -9 on the PID of the python script is
  also clean, thanks to the auto_unmount option.
- Please Note
  - The use of urllib2 may be a performance bottleneck.
  - Single-threading may be a performance bottleneck.


FILE PATH RULES STUFF (not done implementing yet):
- If there is no filepathrule= set in the config file, then behavior is flat workfiles using their IDs.
- rules=myrule will fetch the FilePathRule "myrule" from Operend and present files according to it.
- rules=myrule1,myrule2 will fetch the FilePathRules "myrule1" and "myrule2" from GeneHive and present files according to them.
- rules=myrule* will fetch and use all FilePathRules starting with "myrule", which would include myrule1,myrule2 if those exist. This is only for a trailing asterisk, not a non-trailing asterisk or any other type of wildcard.
- When multiple rules or entities create overlapping paths to separate files, those paths form an appropriately branching directory tree.
- When multiple rules or entities create the same path to different files, priority amongst them is decided arbitrarily.
- Currently, file path rules are applied once when ENTITYFS starts up, and (optionally) on the next access after the refresh_file named in the configuration file gets deleted, recreated, or has its modification time changed. refresh_file operation is new and experimental.

QuickStart:
1) Ensure using python 3.9.7
2) Ensure fuse3, libfuse3-dev and python3-dev are installed
3) Install virtual a virtual env
    pip install -m venv venvname
4) Install System Pre-Reqs (assuming Ubuntu):
    pip install -r requirements.txt
4) Configure. Edit example.ini with changes:
  url=http://whereeverthisisrunning.com/v2
  rules=sequenceTree (assuming this exists - it most likely doesnt)
5) Start:
  ./start.sh
  directories and file will be in the mountpoint directory
6) Stop:
  ./stop.sh
  




