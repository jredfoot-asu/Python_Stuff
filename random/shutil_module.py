import shutil
import zipfile
import requests

#write files individually to a folder named files.zip. All files live in the same directory
# my_zip = zipfile.ZipFile('files.zip', 'w')
# my_zip.write('test.txt')
# my_zip.write('dogs.jpg')
# my_zip.close

#using context manager to do the same thing above.
# with zipfile.ZipFile('files.zip', 'w') as my_zip:
#     my_zip.write("test.txt")
#     my_zip.write('dogs.jpg')

#to compress a zipfile ad the compression argument to the statement.
# with zipfile.ZipFile('files.zip', 'w', compression=zipfile.ZIP_DEFLATED) as my_zip:
#     my_zip.write("test.txt")
#     my_zip.write('dogs.jpg')

#looking at the files that are contained in a zip file.
# with zipfile.ZipFile('files.zip', 'r') as my_zip:
    # shows the files in the zip file.
    # print(my_zip.namelist())
    # extracts the files into a directory named "files."
    # my_zip.extractall('files')
    # extract one specific file.
    # my_zip.extract('dogs.jpg')

"""
create a zip file. 3 arguments are the file name you want to create, the format you want to create it with, and the file you are going to pull from. This is for entire directories and not for just single files.
"""
# shutil.make_archive('another', 'zip', 'files')

# shutil.unpack_archive('files.zip', 'another')

"""
Different archive file formats:

zip: ZIP file.

tar: uncompressed tar file.

gztar: gzip'ed tar-file.

bztar: bzip2'ed tar-file.

xztar: xz'ed tar-file.
"""

# shutil.make_archive('another', 'gztar', 'files')

# shutil.unpack_archive('another.tar.gz', 'another')


#pull a repository for github using a download link.
r = requests.get('https://github.com/jredfoot-asu/html-css-bootstrap-class/archive/refs/heads/master.zip')

#write the file contents of the link above to a file called data.zip.
with open('data.zip', 'wb') as f:
    f.write(r.content)

"""
The print statement shows the contents of the file and the data_zip.extractall statement pulls the files out of the zip folder. If you wanted to name the file something specific you would put the name in the () after extractall.
"""
with zipfile.ZipFile('data.zip', 'r') as data_zip:
    print(data_zip.namelist())
    data_zip.extractall()