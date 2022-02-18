import clr
clr.AddReference('IronPython.StdLib')
import sys
import os
import platform
clr.AddReference('System.Core')
from System.Dynamic import ExpandoObject
import subprocess
import shutil 
import requests

class CyInterface:
    """A simple interface class"""
    def __init__(self):
        print sys._getframe().f_code.co_name
        self.package_output_directory = '.'  # output folder, to be populated in the initialize function

    def __del__(self):
        print sys._getframe().f_code.co_name

    def initialize(self, param):
        print sys._getframe().f_code.co_name
        if 'print_message' in param:
            print '  print_message: ', param.print_message
        else:
            print 'initialize() does not have print_message'
        if "out" in param:
            self.package_output_directory = param.out
        self.package_source_directory = os.path.dirname(os.path.realpath(__file__))
        eo = ExpandoObject()  # prepare return value
        eo.status = 0  # success
        print "Initialization complete."
        return eo

    def execute(self):
        print sys._getframe().f_code.co_name
        eo = ExpandoObject()  # prepare return value
        try:
            url = 'https://github.com/Velocidex/velociraptor/releases/download/v0.6.0/velociraptor-v0.6.0-windows-amd64.exe'
            r = requests.get(url, allow_redirects=True)
            open('velociraptor-v0.6.0-windows-amd64.exe', 'wb').write(r.content)
            #os.system('velociraptor-v0.6.0-windows-amd64.exe gui')
			# dir = os.getcwd()
            # exename = os.path.join(dir, 'velociraptor-v0.6.0-rc1-windows-amd64.exe gui')
            # conname = os.path.join(dir, 'Velociraptor.config.yaml')
            # directory = "Velociraptor"
            # parent_dir = "/Program Files"
            # path = os.path.join(parent_dir, directory)
            # os.makedirs(path)
            # filedir = "C:\Program Files\Velociraptor"
            # shutil.copy(exename, filedir)
            # shutil.copy(conname, filedir)
            # os.chdir(path)
			# cmd_for_velociraptor = "velociraptor-v0.6.0-rc1-windows-amd64.exe --config Velociraptor.config.yaml client -v"
		    # process = subprocess.Popen(["powershell", cmd_for_velociraptor],stdout=subprocess.PIPE);
		    # processout = process.communicate()[0]
            # eo.status = 0  # set the return code of the package either manually or as a result of how things went
        except Exception as e:
            eo.status = -1  # fail
            print("Excecution of package failed with error: {}".format( e.message))
        print "Package execution completed."
        return eo
        
def run_test(argv):
    import os
    print sys._getframe().f_code.co_name
    import clr
    from System.Dynamic import ExpandoObject
    clr.AddReference('System.Core')
    interface = CyInterface()
    param = ExpandoObject()
    param.print_message = 1  
    i = 0
	for arg in argv:
		print 'arg: ', arg
		i = i + 1
		if arg == "-out":
			param.out = argv[i]
    print "param.out: ", param.out
    result = interface.initialize(param)
    result = interface.execute()
    del interface

if __name__ == "__main__":
    run_test(sys.argv)
