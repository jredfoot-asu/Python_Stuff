import sys

print(sys.platform) #shows the system platform.
print(sys.maxint) #Shows the maximim intiger size
print(sys.version) #Shows the system version. 

#To change where the file looks, you can set the path to an alternate folder. It looks like sys.path[0] = whatever path...
# This change is only valid for this instance of the script, once the script is complete, the path reverts.
print(sys.path) #shows the paths that the files are looked into to interperet the python files.

