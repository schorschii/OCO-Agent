#!/usr/bin/python3
import subprocess, time, os, sys, signal, win32serviceutil, win32service, win32event, servicemanager

# OCO Agent: Service Wrapper for Windows

class OcoWinService(win32serviceutil.ServiceFramework):
	_svc_name_ = "oco-agent"
	_svc_display_name_ = "OCO Agent"
	_svc_description_ = "Open Computer Orchestration Agent for Windows (c) Georg Sieber 2020-2022"

	runflag = True
	process = None

	LOG_FILE = None

	def __init__(self,args):
		win32serviceutil.ServiceFramework.__init__(self, *args)
		self.stop_event = win32event.CreateEvent(None, 0, 0, None)
		self.log('Service Initialized.')

	def log(self, msg):
		if self.LOG_FILE is None:
			print(msg)
		else:
			with open(self.LOG_FILE, 'a') as f: f.write(str(msg)+'\n')

	def SvcStop(self):
		self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
		self.runflag = False
		win32event.SetEvent(self.stop_event)

	def SvcDoRun(self):
		self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
		try:
			self.start()
			self.ReportServiceStatus(win32service.SERVICE_RUNNING)
			self.main()
			win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
		except Exception as e:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			self.log('Exception '+str(exc_tb.tb_lineno)+':'+str(e))
			self.SvcStop()

	def start(self):
		self.process = subprocess.Popen([
			"C:/Program Files/OCO Agent/oco-agent.exe", "--daemon",
			"--config=C:/Program Files/OCO Agent/oco-agent.ini"
		])

	def main(self):
		while True:
			# check if child is still alive
			if(self.runflag):
				try:
					if(self.process.poll() is None):
						self.log("Service running...")
					else:
						self.log("Child died! Restart...")
						self.start()
				except Exception as e:
					self.log(str(e))

			# check if we should shut down
			else:
				if(self.process.poll() is None):
					self.log('Child is running and must be killed.')
					# this call also kills subprocesses. Windows halt...
					subprocess.call(['taskkill', '/F', '/T', '/PID',  str(self.process.pid)])
				self.log('Service has stopped.')
				self.ReportServiceStatus(win32service.SERVICE_STOPPED)
				sys.exit()

			time.sleep(1)

if __name__ == '__main__':
	if len(sys.argv) == 1:
		servicemanager.Initialize()
		servicemanager.PrepareToHostSingle(OcoWinService)
		servicemanager.StartServiceCtrlDispatcher()
	else:
		win32serviceutil.HandleCommandLine(OcoWinService)
