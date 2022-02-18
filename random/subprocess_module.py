import subprocess

#if runing windows, you will need to add a shell=True statement.
#The capture_output will work with the .stdout to give the output of the arguments. 
#The text=True converts the output from bytes to a text string that is more readable.
#p1 = subprocess.run(['ls', '-la'], capture_output=True, text=True)

#adding .arg will give you the arguments thatere passed.
#adding .returncode will give you the return code of the program and will tell you if the process was successful or not.
#adding .stdout gives the output of the arguments. The .decode will convert the bytes to a string. 
#print(p1.stdout)

#This will take the output of the stdout and print it to a file. 
# with open('output.txt', 'w') as f:
#     p1 = subprocess.run(['ls', '-la'], stdout=f, text=True)

#trying to look into a directory that doesn't exist
#The check=True will have python throw an error. By default, python will not trow an error, it will simply error in the background.
#p1 = subprocess.run(['ls', '-la', 'dne'], capture_output=True, text=True, check=True)
#redirects the error to DEVNULL so the error doesn't effect the program.
#p1 = subprocess.run(['ls', '-la', 'dne'], stderr=DEVNULL)
#Shows the error that occurred because the file doesn't exist.
#print(p1.stderr)

#grab a file and open it in the cat program
# p1 = subprocess.run(['cat', 'test.txt'], capture_output=True, text=True)
#print(p1.stdout)

#using grep, we look for the word test in the file. We us stdout as the input to grep.
# p2 = subprocess.run(['grep', '-n', 'test'], capture_output=True, text=True, input=p1.stdout)
# print(p2.stdout)

#to get the same result as above with a string instead of a list:
# p1 = subprocess.run('cat test.txt | grep -n test', capture_output=True, text=True, shell=True)
# print(p1.stdout)

# to use on python 2.7:

p1 = subprocess.call(['ls', '-la'])
#print(p1)

#to create a file with the output of the command.
#if you want the error to output to the text file, use stderr=STDOUT
#syntax would look like subprocess.call(['ls'], stdout=file_object, stderr=STDOUT)
# file_object = open('stdout.txt', 'w')
# subprocess.call(['ls'], stdout=file_object)
# file_object.close

display = subprocess.check_output(['ls'])
print(display)