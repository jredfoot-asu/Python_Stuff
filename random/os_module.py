import os
from datetime import datetime

#prints all of the attributes within a module.
#print(dir(os))

#gets current working directory
print(os.getcwd())

#navigate to desktop
os.chdir('/Users/jredfoot/Desktop')
print(os.getcwd())

#List Directories in the directory that you are in. Because we just changed to Desktop, this will be the desktop directories.
print(os.listdir())

#Create a new folder on the desktop. 2 Different methods.
#mkdir on creates this one file.
os.mkdir("OS-Demo-2")
#makedirs can create subdirectories within the directory you are also making
os.makedirs("OS-Demo-3/Sub-Dir-1")
print(os.listdir())

#delete folders
#will delete the top leve folder and will error if there are sub folders.
os.rmdir('OS-Demo-2')
#will delete all files and folders in the path.
os.removedirs('OS-Demo-3/Sub-Dir-1')

#rename a folder
#the arguments are in the first field you put the name of the file you want to change, the second argument is the name you want to change the file to.
# os.rename(first_file_name, new_name_of_file)

#print file information
#add .st_size behind the file name like so: os.stat("Cylance User API Guide v2.0 rev24.pdf").st_size to get the file size in bytes.
#add .st_mtime to get the last modification time. When you print the os.stat base, you can see these as a list and choose the ones you want. Search for what they mean to know what you are printing off.
print(os.stat("Cylance User API Guide v2.0 rev24.pdf"))

#to get a human readable timestamp of the file.
mod_time = os.stat("Cylance User API Guide v2.0 rev24.pdf").st_mtime
print(datetime.fromtimestamp(mod_time))

#to see the entire directory tree on the sytem.
# for dirpath, dirnames, filenames in os.walk("/Users/jredfoot/Desktop"):
#     print("Current Path", dirpath)
#     print("Directories", dirnames)
#     print("Files", filenames)
#     print()

#gets the environment variables, in this case it's the HOME environment variable.
print(os.environ.get('HOME'))

#create a file in the home environment.
#the .join allows you to join 2 arguments, a path and then a file name.
file_path = os.path.join(os.environ.get('HOME'), 'test.txt')
print(file_path)

#writes the file.
# with open(file_path, "w") as f:
#     f.write()
#     f.close()

#prints the file information based on what you input. Basename is the file name, dirname is the directory name. Split prints both.
print(os.path.basename('/tmp/test.text'))
print(os.path.dirname('/tmp/test.txt'))
print(os.path.split('/tmp/test.txt'))

#check existance of a file path. Will return boolean. The .isdir and .is file instead of exists will check if the inquiry is a file or directory.
print(os.path.exists('/tmp/test.txt'))

#Split file root and extension.
print(os.path.splitext('/tmp/test.txt'))