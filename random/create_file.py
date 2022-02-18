import os

file_path = os.path.join(os.chdir('C:\\'), 'test.txt')
print(file_path)

with open(file_path, "w") as f:
    text = 'This is some sample text to go into the file.'
    f.write(text)
    f.close()