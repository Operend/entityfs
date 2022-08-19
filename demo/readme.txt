This directory contains the pieces needed for an interactive demo of FilePathRulies in action.

Edit config_tests.js and demo.ini to point at a scratch Operend install and include the relevant credentials. As written, they go to localhost:8080 with superuser "hive" and password "hivesu" - actaully these wont work, you'll need to use a superuser you've created.

populate.js is a Node script that creates:
- an EntityClass named "shape"
- a few WorkFiles of ascii-art shapes
- a metadata Entity defining the color and shape of each workfile
- three FilePathRules exposing the shapes in directories differently
Run this once, after editing config_tests.js appropriately. You may need to 'npm install request' if that package isn't in your default node environment.

start.sh creates a directory "mountpoint" and starts entityfs (as python ../entityfs.py) in it, using this directory's demo.ini as the ENTITYFS_CONFIG file. After running it, you can see under mountpoint a directory tree in which the same files are exposed in a few different arrangements.

stop.sh unmounts mountpoint.

operend.js is a helper file for populate.js (adapted from the operend core server unit tests), and the various other .txt files are just the ASCII art to be used as WorkFiles.



