# -*- coding: utf-8 -*-

from PyQt4 import QtCore, QtGui
from threading import Thread
import time
import sys
import nmap
from string import digits, ascii_lowercase, ascii_uppercase
import os
import re
import subprocess


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)





class Ui_MainWindow(object):


    def openlistip(self):


        self.ipv = ""

        self.save = QtGui.QFileDialog.getOpenFileName()

        fileformat = (os.popen("file '%s'" %self.save)).read()

        if "ASCII text" in fileformat:

            self.ip = open(self.save, 'r').read()

            ipcont = re.search(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                self.ip)

            if ipcont is None:
                self.message("Wrong File ! ", "Please Ip List File", Warning)
            else:

                self.ip = self.ip.replace("\n", " ")
                self.ipv += self.ip
                self.ipv2 = str(self.ipv)

                self.host.setText("1.3.3.7")
                self.progressBar.setText("All Host Added")
        else:
            self.message("Wrong Format ! ", "Please Text File", Warning)


    def k9999(self):

        self.gakidou = ""
        self.gakidou += self.host.text()
        self.gakidou2 = str(self.gakidou)

        self.ningendo = ""
        self.ningendo += self.port.text()
        self.ningendo2 = str(self.ningendo)

        hostreg = re.search(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",self.gakidou2)
        portreg = re.search(r"\d{1,5}(?:-\d{1,5})?(\s*,\s*\d{1,5}(?:-\d{1,5})?)*$", self.port.text())
        spooftreg = re.search(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            self.spoofline.text())
        excludetreg = re.search(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            self.excludeline.text())

        if not self.host.text():
            self.message("Free Space ! ", "Please Enter Victim", Warning)
        elif not self.port.text():
            self.message("Free Space ! ", "Please Enter Port", Warning)

        elif hostreg is None:
            self.message("Error Host ! ", "Please Enter Ip Adress", SyntaxError)
        elif portreg is None:
            self.message("Error Port ! ", "Please Enter Port Number", SyntaxError)

        elif self.delayscan.isChecked() == True and not self.delayspin.value():
            self.message("Free Space ! ", "Please Enter Delayspin Value", Warning)
        elif self.maxnumpacks.isChecked() == True and not self.maxnumspin.value():
            self.message("Free Space ! ", "Please Enter Max Num Value", Warning)
        elif self.fastscan.isChecked() == True and not self.fastspin.value():
            self.message("Free Space ! ", "Please Enter Fast Scan Value", Warning)
        elif self.datalength.isChecked() == True and not self.datalenspin.value():
            self.message("Free Space ! ", "Please Enter Data Length Value", Warning)
        elif self.fragment.isChecked() == True and not self.fragmentspin.value():
            self.message("Free Space ! ", "Please Enter Fragment Value", Warning)
        elif self.spoof.isChecked() == True and not  self.spoofline.text():
            self.message("Free Space ! ", "Please Enter Spoof Value", Warning)
        elif self.spoof.isChecked() == True and spooftreg == None:
            self.message("Error Spoof Host Value ! ", "Please Enter Spoof Ip", Warning)
        elif self.parallelism.isChecked() == True and not self.parallelismspin.value():
            self.message("Free Space ! ", "Please Enter Parallelism Value", Warning)
        elif self.excludeip.isChecked() == True and not self.excludeline.text():
            self.message("Free Space ! ", "Please Enter Exclude Ip/s", Warning)
        elif self.excludeip.isChecked() == True and excludetreg == None:
            self.message("Error Exclude Host Value !", "Please Enter Exclude Ip", Warning)
        elif self.yourcommand.isChecked() == True and not self.yourline.text():
            self.message("Free Space !", "Please Enter Your Command", Warning)
        elif self.timeout.isChecked() == True and not self.timeoutspin.value():
            self.message("Free Space !", "Please Enter Timeout Value", Warning)



        else:

            self.allcommand = ""

            if self.maxhost.isChecked():
                self.allcommand += " --max-hostgroup "+'%s' %self.maxspin.value()
            if self.yourcommand.isChecked() == True:
                self.allcommand += self.yourline.text()

            if self.excludeip.isChecked() == True:
                self.excludeline.setReadOnly(False)
                self.allcommand += " --exclude "+'%s' %self.excludeline.text()
            if self.justopen.isChecked() == True:
                self.allcommand += " --open"
            if self.allup.isChecked() == True:
                self.allcommand += " -O"
            if self.timeout.isChecked() == True:
                self.allcommand += " --host-timeout "+'%s' %self.timeoutspin.value()
            if self.synscan.isChecked() == True:
                self.allcommand += " -sS"
            if self.versionchck.isChecked() == True:
                self.allcommand += " -sV"
            if self.fastscan.isChecked() == True:
                self.fastspin.setReadOnly(False)
                self.allcommand += " -T"+'%s' %self.fastspin.value()
            if self.parallelism.isChecked() == True:
                self.parallelismspin.setReadOnly(False)
                self.allcommand += " --max-parallelism "+'%s' %self.parallelismspin.value()
            if self.delayscan.isChecked() == True:
                self.delayspin.setReadOnly(False)
                self.allcommand += " --scan-delay "+'%s' %self.delayspin.value()

            if self.maxnumpacks.isChecked() == True:
                self.maxnumspin.setReadOnly(False)
                self.allcommand += " --max-rate "+'%s' %self.maxnumspin.value()
            if self.randomscan.isChecked() == True:

                self.allcommand += " -A"
            if self.datalength.isChecked() == True:
                self.datalenspin.setReadOnly(False)
                self.allcommand += " --data-length "+'%s' %self.datalenspin.value()
            if self.fragment.isChecked() == True:
                self.fragmentspin.setReadOnly(False)
                self.allcommand += " -f --mtu "+'%s' %self.fragmentspin.value()
            if self.spoof.isChecked() == True:
                self.spoofline.setReadOnly(False)
                self.allcommand += " -D "+'%s' %self.spoofline.text()

            if self.ipv2 > 0:
                t = Thread(target=self.scanner, args=(self.ipv2,))
                t.daemon = True
                t.start()
            else:
                t = Thread(target=self.scanner, args=(self.gakidou2,))
                t.daemon = True
                t.start()


    def scanner(self,hst):

        self.progressBar.setText("Scannig Started ! Please Wait..")
        self.a = time.time()

        self.sc = nmap.PortScanner()

        self.sc.scan(hosts=hst, ports=self.ningendo2, arguments='%s' % self.allcommand)

        if "(0 hosts up)" in self.sc.get_nmap_last_output():
            self.progressBar.setText("Scannig Finish ! 0 Host Up")

        else:

            for self.gakidou2 in self.sc.all_hosts():
                if 'osmatch' in self.sc[self.gakidou2]:
                    for osmatch in self.sc[self.gakidou2]['osmatch']:
                        pass

                    for osclass in osmatch['osclass']:
                        self.ipachi = QtGui.QTreeWidgetItem(self.treeWidget)
                        self.ipachi.setText(0, self.gakidou2)
                        self.hostcount += 1

                        self.iplst.append(self.gakidou2)

                        try:
                            if "Windows" in osclass['osfamily']:
                                self.ipachi.setIcon(0, QtGui.QIcon('osimage/windows.png'))
                            elif "Linux" in osclass['osfamily']:
                                self.ipachi.setIcon(0, QtGui.QIcon('osimage/linux.png'))
                            elif "embedded" in osclass['osfamily']:
                                self.ipachi.setIcon(0, QtGui.QIcon('osimage/embed.png'))

                            self.append()
                        except:
                            pass

                else:

                    self.ipachi = QtGui.QTreeWidgetItem(self.treeWidget)
                    self.ipachi.setText(0, self.gakidou2)
                    self.hostcount += 1
                    self.ipachi.setIcon(0, QtGui.QIcon('osimage/embed.png'))
                    self.iplst.append(self.gakidou2)
                    self.append()
                    self.ipv2 = 0

            self.cvssaw += self.sc.csv()


    def append(self):

            for proto in self.sc[self.gakidou2].all_protocols():

                ports = self.sc[self.gakidou2][proto].keys()
                sort = sorted(ports)


                for port in sort:

                        self.items = QtGui.QTreeWidgetItem(self.ipachi)


                        self.esc = self.items.setText(0, str(port)+" "+self.sc[self.gakidou2][proto][port]['name'].title())
                        self.items.setText(1, self.sc[self.gakidou2][proto][port]['state'].title())


                        self.items.setText(2, self.sc[self.gakidou2][proto][port]['product'].title()+" "+self.sc[self.gakidou2][proto][port]['version'].title())

                        if "21" in self.items.text(0):
                            if self.items.text(1) == "Open":
                                self.ftptext.append(self.gakidou2)
                        if "22" in self.items.text(0):
                            if self.items.text(1) == "Open":
                                self.sshtext.append(self.gakidou2)
                        if "3389" in self.items.text(0):
                            if self.items.text(1) == "Open":
                                self.rdptext.append(self.gakidou2)
                        if "445" in self.items.text(0):
                            if self.items.text(1) == "Open":
                                self.smbtext.append(self.gakidou2)
                        if "80" in self.items.text(0):
                            if self.items.text(1) == "Open":
                                self.httptext.append(self.gakidou2)

            self.progressBar.setText("Scannig Finish ! "+ "["+str(self.hostcount)+"]" +" Host UP")


    def clearCustom(self):

        self.customlist.clear()

    def saveCustom(self):

        try:

            self.saveca = QtGui.QFileDialog.getSaveFileName()

            file = open(self.saveca, 'w')
            for i in xrange(self.customlist.count()):
                file.write(''.join([str(self.customlist.item(i).text()), '\n']))

            file.close()

        except: IOError, True


    def Ftp(self):

        self.customlist.addItems(self.ftptext)
    def Rdp(self):

        self.customlist.addItems(self.rdptext)
    def Ssh(self):

        self.customlist.addItems(self.sshtext)
    def Http(self):

        self.customlist.addItems(self.httptext)
    def Smb(self):

        self.customlist.addItems(self.smbtext)


    def scanout(self):

        self.keyo = str(self.host.text())

        self.keys = self.keyo+".html"

        if self.output.isChecked() == False:
            self.message("No Checked Output !", " ", "Warning")
        if self.output.isChecked() == True and self.outputfor.currentText() == "-XML-":
            with open(self.keyo, "w") as f:
                f.write(self.sc.get_nmap_last_output())
                f.close()
                self.message("Output Saved !",self.keyo,"INFO")
        if self.output.isChecked() == True and self.outputfor.currentText() == "-HTML-":
            with open(self.keyo, "w") as f:
                f.write(self.sc.get_nmap_last_output())
                f.close()
                os.system("xsltproc '%s' -o '%s'" %(self.keyo,self.keys))
                self.message("Output Saved !", self.keys , "INFO")

    def cvs(self):

        try:

            self.savecv = QtGui.QFileDialog.getSaveFileName()

            file = open(self.savecv, 'w')
            file.write(self.cvssaw)
            file.close()

        except: IOError, True

    def ftp(self):

        pass

    def saveip(self):

        try:

            for x in self.iplst:

                self.b += (x+'\n')
            print(self.b)

            self.killip = QtGui.QFileDialog.getSaveFileName()

            file = open(self.killip, 'w')
            file.write(self.b)
            file.close()

        except: None


    def message(self,text,inf,title):
         self.msg = QtGui.QMessageBox()
         self.msg.setText('%s' %text)
         self.msg.setInformativeText('%s' %inf)
         self.msg.setWindowTitle('%s' %title)

         self.execmsg = self.msg.exec_()



    def message2(self):
         self.msg = QtGui.QMessageBox()
         self.msg.setText("192.168.2.1\n192.168.2.0/24\n192.168.2.0-20\n192.168.2.1 192.168.2.23")
         self.msg.setInformativeText("Example Victim")
         self.msg.setWindowTitle("INFO")

         self.execmsg = self.msg.exec_()

    def message3(self):
         self.msg = QtGui.QMessageBox()
         self.msg.setText("443,445\n21-443")
         self.msg.setInformativeText("Example Victim Port")
         self.msg.setWindowTitle("INFO")

         self.execmsg = self.msg.exec_()


    def toggle(self):


        self.justopen.toggle()
        self.synscan.toggle()
        self.versionchck.toggle()

    def help(self):

        self.message("Pynmap", "<font color='white'><p><b>Coded : Abdulaziz Altuntas - Gh:@azizaltuntas</b></p>", "INFO")


    def disable(self):

        self.parallelism.setEnabled(False)
        self.defaultscan.setEnabled(False)
        self.maxhost.setEnabled(False)
        self.versionchck.setEnabled(False)
        self.timeout.setEnabled(False)
        self.maxnumpacks.setEnabled(False)
        self.fragment.setEnabled(False)
        self.delayscan.setEnabled(False)
        self.justopen.setEnabled(False)
        self.synscan.setEnabled(False)
        self.allup.setEnabled(False)
        self.fastscan.setEnabled(False)
        self.randomscan.setEnabled(False)
        self.spoof.setEnabled(False)
        self.datalength.setEnabled(False)
        self.parallelism.setChecked(False)
        self.defaultscan.setChecked(False)
        self.maxhost.setChecked(False)
        self.versionchck.setChecked(False)
        self.maxnumpacks.setChecked(False)
        self.fragment.setChecked(False)
        self.delayscan.setChecked(False)
        self.justopen.setChecked(False)
        self.synscan.setChecked(False)
        self.allup.setChecked(False)
        self.fastscan.setChecked(False)
        self.randomscan.setChecked(False)
        self.datalength.setChecked(False)
        self.spoof.setChecked(False)



        if self.yourcommand.isChecked() == False:
            win.setupUi(cls)

    def stopsession(self):
        os.system("killall -9 nmap")
        self.progressBar.setText("ALL NMAP KILLED")

    def resettool(self):
        win.setupUi(cls)

    def setupUi(self, MainWindow):

        self.ftptext = []
        self.rdptext = []
        self.smbtext = []
        self.sshtext = []
        self.httptext = []
        self.cvssaw = ""
        self.ipv2 = 0
        self.b = ""
        self.iplst = []
        self.hostcount = 0
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(1139, 589)
        MainWindow.setMinimumSize(QtCore.QSize(1139, 589))
        MainWindow.setMaximumSize(QtCore.QSize(1139, 589))
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.groupBox_4 = QtGui.QGroupBox(self.centralwidget)
        self.groupBox_4.setGeometry(QtCore.QRect(190, 240, 771, 311))
        self.groupBox_4.setObjectName(_fromUtf8("groupBox_4"))
        self.label_3 = QtGui.QLabel(self.groupBox_4)
        self.label_3.setGeometry(QtCore.QRect(320, 170, 56, 17))
        self.label_3.setLineWidth(1)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.groupBox = QtGui.QGroupBox(self.groupBox_4)
        self.groupBox.setGeometry(QtCore.QRect(0, 30, 141, 261))
        self.groupBox.setObjectName(_fromUtf8("groupBox"))

        self.groupBox_3 = QtGui.QGroupBox(self.groupBox_4)
        self.groupBox_3.setGeometry(QtCore.QRect(340, 30, 141, 241))
        self.groupBox_3.setObjectName(_fromUtf8("groupBox_3"))

        self.label_3.raise_()
        self.label_2 = QtGui.QLabel(self.groupBox_4)
        self.label_2.setGeometry(QtCore.QRect(150, 170, 56, 17))
        self.label_2.setLineWidth(1)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.groupBox_5 = QtGui.QGroupBox(self.groupBox_4)
        self.groupBox_5.setGeometry(QtCore.QRect(610, 30, 141, 251))
        self.groupBox_5.setObjectName(_fromUtf8("groupBox_5"))
        self.customlist = QtGui.QListWidget(self.groupBox_5)
        self.customlist.setGeometry(QtCore.QRect(0, 31, 141, 241))
        self.customlist.viewport().setProperty("cursor", QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.customlist.setObjectName(_fromUtf8("customlist"))
        self.getftp = QtGui.QPushButton(self.groupBox_4)
        self.getftp.setGeometry(QtCore.QRect(500, 60, 85, 27))
        self.getftp.setObjectName(_fromUtf8("getftp"))
        self.getssh = QtGui.QPushButton(self.groupBox_4)
        self.getssh.setGeometry(QtCore.QRect(500, 100, 85, 27))
        self.getssh.setObjectName(_fromUtf8("getssh"))
        self.getsmb = QtGui.QPushButton(self.groupBox_4)
        self.getsmb.setGeometry(QtCore.QRect(500, 140, 85, 27))
        self.getsmb.setObjectName(_fromUtf8("getsmb"))
        self.getrdp = QtGui.QPushButton(self.groupBox_4)
        self.getrdp.setGeometry(QtCore.QRect(500, 180, 85, 27))
        self.getrdp.setObjectName(_fromUtf8("getrdp")),
        #self.otherspin = QtGui.QSpinBox(self.groupBox_4)
        #self.otherspin.setGeometry(QtCore.QRect(500, 240, 48, 21))
        #self.otherspin.setObjectName(_fromUtf8("otherspin"))
        self.getother = QtGui.QPushButton(self.groupBox_4)
        self.getother.setGeometry(QtCore.QRect(500, 220, 85, 27))
        self.getother.setObjectName(_fromUtf8("getother"))
        #self.label_5 = QtGui.QLabel(self.groupBox_4)
        #self.label_5.setGeometry(QtCore.QRect(510, 220, 71, 20))
        #self.label_5.setObjectName(_fromUtf8("label_5"))


        self.label_7 = QtGui.QLabel(self.groupBox_4)
        self.label_7.setGeometry(QtCore.QRect(760, 150, 56, 17))
        self.label_7.setLineWidth(1)
        self.label_7.setObjectName(_fromUtf8("label_7"))
        self.groupBox_6 = QtGui.QGroupBox(self.centralwidget)
        self.groupBox_6.setGeometry(QtCore.QRect(420, 0, 371, 231))
        self.groupBox_6.setObjectName(_fromUtf8("groupBox_6"))
        self.yourline = QtGui.QLineEdit(self.groupBox_6)
        self.yourline.setGeometry(QtCore.QRect(120, 50, 241, 21))
        self.yourline.setObjectName(_fromUtf8("yourline"))
        self.yourcommand = QtGui.QCheckBox(self.groupBox_6)
        self.yourcommand.setGeometry(QtCore.QRect(0, 50, 121, 22))
        self.yourcommand.setObjectName(_fromUtf8("yourcommand"))
        self.versionchck = QtGui.QCheckBox(self.groupBox_6)
        self.versionchck.setGeometry(QtCore.QRect(120, 170, 111, 22))
        self.versionchck.setObjectName(_fromUtf8("versionchck"))
        self.excludeip = QtGui.QCheckBox(self.groupBox_6)
        self.excludeip.setGeometry(QtCore.QRect(0, 80, 111, 22))
        self.excludeip.setObjectName(_fromUtf8("excludeip"))
        self.output = QtGui.QCheckBox(self.groupBox_6)
        self.output.setGeometry(QtCore.QRect(0, 110, 111, 22))
        self.output.setObjectName(_fromUtf8("output"))
        self.excludeline = QtGui.QLineEdit(self.groupBox_6)
        self.excludeline.setGeometry(QtCore.QRect(120, 80, 241, 21))
        self.excludeline.setObjectName(_fromUtf8("excludeline"))
        self.outputfor = QtGui.QComboBox(self.groupBox_6)
        self.outputfor.setGeometry(QtCore.QRect(120, 110, 70, 21))
        self.outputfor.setObjectName(_fromUtf8("outputfor"))
        self.outputfor.addItem(_fromUtf8(""))
        self.outputfor.addItem(_fromUtf8(""))


        self.justopen = QtGui.QCheckBox(self.groupBox_6)
        self.justopen.setGeometry(QtCore.QRect(0, 140, 111, 22))
        self.justopen.setObjectName(_fromUtf8("justopen"))
        self.synscan = QtGui.QCheckBox(self.groupBox_6)
        self.synscan.setGeometry(QtCore.QRect(0, 170, 111, 22))
        self.synscan.setObjectName(_fromUtf8("synscan"))
        self.defaultscan = QtGui.QCheckBox(self.groupBox_6)
        self.defaultscan.setGeometry(QtCore.QRect(0, 20, 111, 22))
        self.defaultscan.setObjectName(_fromUtf8("defaultscan"))
        self.allup = QtGui.QCheckBox(self.groupBox_6)
        self.allup.setGeometry(QtCore.QRect(0, 200, 121, 22))
        self.allup.setObjectName(_fromUtf8("allup"))

        self.maxhost = QtGui.QCheckBox(self.groupBox_6)
        self.maxhost.setGeometry(QtCore.QRect(120, 140, 121, 22))
        self.maxhost.setObjectName(_fromUtf8("maxhost"))
        self.maxspin = QtGui.QSpinBox(self.groupBox_6)
        self.maxspin.setGeometry(QtCore.QRect(210, 140, 41, 21))
        self.maxspin.setObjectName(_fromUtf8("maxspin"))
        self.maxspin.setRange(1,30)

        self.fastscan = QtGui.QCheckBox(self.groupBox_6)
        self.fastscan.setGeometry(QtCore.QRect(120, 200, 91, 22))
        self.fastscan.setObjectName(_fromUtf8("fastscan"))
        self.fastspin = QtGui.QSpinBox(self.groupBox_6)
        self.fastspin.setGeometry(QtCore.QRect(210, 200, 41, 21))
        self.fastspin.setObjectName(_fromUtf8("fastspin"))
        self.fastspin.setRange(1,5)
        self.groupBox_7 = QtGui.QGroupBox(self.centralwidget)
        self.groupBox_7.setGeometry(QtCore.QRect(9, 0, 401, 201))
        self.groupBox_7.setObjectName(_fromUtf8("groupBox_7"))
        self.openlist = QtGui.QPushButton(self.groupBox_7)
        self.openlist.setGeometry(QtCore.QRect(330, 20, 71, 21))
        self.openlist.setObjectName(_fromUtf8("openlist"))

        self.label = QtGui.QLabel(self.groupBox_7)
        self.label.setGeometry(QtCore.QRect(0, 20, 61, 17))
        self.label.setObjectName(_fromUtf8("label"))
        self.porthelp = QtGui.QPushButton(self.groupBox_7)
        self.porthelp.setGeometry(QtCore.QRect(310, 60, 21, 21))
        self.porthelp.setObjectName(_fromUtf8("porthelp"))
        self.label_4 = QtGui.QLabel(self.groupBox_7)
        self.label_4.setGeometry(QtCore.QRect(0, 60, 61, 17))
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.hosthelp = QtGui.QPushButton(self.groupBox_7)
        self.hosthelp.setGeometry(QtCore.QRect(310, 20, 21, 21))
        self.hosthelp.setObjectName(_fromUtf8("hosthelp"))
        self.host = QtGui.QLineEdit(self.groupBox_7)
        self.host.setGeometry(QtCore.QRect(70, 20, 241, 21))
        self.host.setObjectName(_fromUtf8("host"))
        self.port = QtGui.QLineEdit(self.groupBox_7)
        self.port.setGeometry(QtCore.QRect(70, 60, 241, 21))
        self.port.setObjectName(_fromUtf8("port"))
        self.start = QtGui.QPushButton(self.groupBox_7)
        self.start.setGeometry(QtCore.QRect(70, 170, 85, 27))
        self.start.setObjectName(_fromUtf8("start"))
        self.stop = QtGui.QPushButton(self.groupBox_7)
        self.stop.setGeometry(QtCore.QRect(220, 170, 85, 27))
        self.stop.setObjectName(_fromUtf8("stop"))
        self.reset = QtGui.QPushButton(self.centralwidget)
        self.reset.setGeometry(QtCore.QRect(150, 210, 85, 27))
        self.reset.setObjectName(_fromUtf8("reset"))
        self.progressBar = QtGui.QLineEdit(self.groupBox_7)
        self.progressBar.setGeometry(QtCore.QRect(70, 130, 241, 23))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName(_fromUtf8("progressBar"))
        self.label_6 = QtGui.QLabel(self.groupBox_7)
        self.label_6.setGeometry(QtCore.QRect(0, 130, 61, 17))
        self.label_6.setObjectName(_fromUtf8("label_6"))
        self.treeWidget = QtGui.QTreeWidget(self.groupBox_4)
        self.treeWidget.setGeometry(QtCore.QRect(0, 50, 481, 231))
        self.treeWidget.setObjectName(_fromUtf8("treeWidget"))

        self.groupBox_8 = QtGui.QGroupBox(self.centralwidget)
        self.groupBox_8.setGeometry(QtCore.QRect(809, -1, 321, 261))
        self.groupBox_8.setObjectName(_fromUtf8("groupBox_8"))
        self.parallelism = QtGui.QCheckBox(self.groupBox_8)
        self.parallelism.setGeometry(QtCore.QRect(0, 20, 101, 22))
        self.parallelism.setObjectName(_fromUtf8("parallelism"))
        self.parallelismspin = QtGui.QSpinBox(self.groupBox_8)
        self.parallelismspin.setGeometry(QtCore.QRect(130, 20, 51, 21))
        self.parallelismspin.setObjectName(_fromUtf8("parallelismspin"))

        self.timeout = QtGui.QCheckBox(self.groupBox_8)
        self.timeout.setGeometry(QtCore.QRect(185, 20, 101, 22))
        self.timeout.setObjectName(_fromUtf8("timeout"))
        self.timeoutspin = QtGui.QSpinBox(self.groupBox_8)
        self.timeoutspin.setGeometry(QtCore.QRect(265, 20, 51, 21))
        self.timeoutspin.setObjectName(_fromUtf8("timeoutspin"))

        self.delayscan = QtGui.QCheckBox(self.groupBox_8)
        self.delayscan.setGeometry(QtCore.QRect(0, 50, 101, 22))
        self.delayscan.setObjectName(_fromUtf8("delayscan"))
        self.delayspin = QtGui.QSpinBox(self.groupBox_8)
        self.delayspin.setGeometry(QtCore.QRect(130, 50, 51, 21))
        self.delayspin.setObjectName(_fromUtf8("delayspin"))
        self.maxnumpacks = QtGui.QCheckBox(self.groupBox_8)
        self.maxnumpacks.setGeometry(QtCore.QRect(0, 80, 131, 22))
        self.maxnumpacks.setObjectName(_fromUtf8("maxnumpacks"))
        self.maxnumspin = QtGui.QSpinBox(self.groupBox_8)
        self.maxnumspin.setGeometry(QtCore.QRect(130, 80, 51, 21))
        self.maxnumspin.setObjectName(_fromUtf8("maxnumspin"))


        self.randomscan = QtGui.QCheckBox(self.groupBox_8)
        self.randomscan.setGeometry(QtCore.QRect(0, 110, 131, 22))
        self.randomscan.setObjectName(_fromUtf8("randomscan"))
        self.datalength = QtGui.QCheckBox(self.groupBox_8)
        self.datalength.setGeometry(QtCore.QRect(0, 140, 131, 22))
        self.datalength.setObjectName(_fromUtf8("datalength"))
        self.datalenspin = QtGui.QSpinBox(self.groupBox_8)
        self.datalenspin.setGeometry(QtCore.QRect(130, 140, 51, 21))
        self.datalenspin.setObjectName(_fromUtf8("datalenspin"))
        self.fragment = QtGui.QCheckBox(self.groupBox_8)
        self.fragment.setGeometry(QtCore.QRect(0, 170, 131, 22))
        self.fragment.setObjectName(_fromUtf8("fragment"))
        self.fragmentspin = QtGui.QSpinBox(self.groupBox_8)
        self.fragmentspin.setGeometry(QtCore.QRect(130, 170, 51, 21))
        self.fragmentspin.setObjectName(_fromUtf8("fragmentspin"))
        self.spoofline = QtGui.QLineEdit(self.groupBox_8)
        self.spoofline.setGeometry(QtCore.QRect(120, 200, 201, 21))
        self.spoofline.setObjectName(_fromUtf8("spoofline"))
        self.spoof = QtGui.QCheckBox(self.groupBox_8)
        self.spoof.setGeometry(QtCore.QRect(0, 200, 121, 22))
        self.spoof.setObjectName(_fromUtf8("spoof"))
        self.saveiplst = QtGui.QPushButton(self.centralwidget)
        self.saveiplst.setGeometry(QtCore.QRect(30, 340, 85, 27))
        self.saveiplst.setObjectName(_fromUtf8("saveiplst"))
        self.saveall = QtGui.QPushButton(self.centralwidget)
        self.saveall.setGeometry(QtCore.QRect(30, 380, 85, 27))
        self.saveall.setObjectName(_fromUtf8("saveall"))
        self.savecvs = QtGui.QPushButton(self.centralwidget)
        self.savecvs.setGeometry(QtCore.QRect(30, 420, 85, 27))
        self.savecvs.setObjectName(_fromUtf8("savecvs"))
        self.savecustomip = QtGui.QPushButton(self.centralwidget)
        self.savecustomip.setGeometry(QtCore.QRect(980, 360, 91, 27))
        self.savecustomip.setObjectName(_fromUtf8("savecustomip"))
        self.clearcustomip = QtGui.QPushButton(self.centralwidget)
        self.clearcustomip.setGeometry(QtCore.QRect(980, 410, 91, 27))
        self.clearcustomip.setObjectName(_fromUtf8("clearcustomip"))
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1139, 27))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        self.menuAbout = QtGui.QMenu(self.menubar)
        self.menuAbout.setObjectName(_fromUtf8("menuAbout"))
        MainWindow.setMenuBar(self.menubar)
        self.statusBar = QtGui.QStatusBar(MainWindow)
        self.statusBar.setObjectName(_fromUtf8("statusBar"))
        MainWindow.setStatusBar(self.statusBar)
        self.actionAbout = QtGui.QAction(MainWindow)
        self.actionAbout.setObjectName(_fromUtf8("actionAbout"))
        self.menuAbout.addAction(self.actionAbout)
        self.menubar.addAction(self.menuAbout.menuAction())
        self.start.clicked.connect(self.k9999)
        self.reset.clicked.connect(self.resettool)
        self.hosthelp.clicked.connect(self.message2)
        self.porthelp.clicked.connect(self.message3)
        self.saveiplst.clicked.connect(self.saveip)
        self.openlist.clicked.connect(self.openlistip)
        self.savecvs.clicked.connect(self.cvs)
        self.saveall.clicked.connect(self.scanout)
        self.getftp.clicked.connect(self.Ftp)
        self.getother.clicked.connect(self.Http)
        self.getrdp.clicked.connect(self.Rdp)
        self.getsmb.clicked.connect(self.Smb)
        self.getssh.clicked.connect(self.Ssh)
        self.savecustomip.clicked.connect(self.saveCustom)
        self.clearcustomip.clicked.connect(self.clearCustom)
        self.stop.clicked.connect(self.stopsession)


        self.excludeline.setEnabled(False)
        self.outputfor.setEnabled(False)
        self.yourline.setEnabled(False)
        self.spoofline.setEnabled(False)
        self.fastspin.setEnabled(False)
        self.fragmentspin.setEnabled(False)
        self.timeoutspin.setEnabled(False)
        self.maxspin.setEnabled(False)
        self.datalenspin.setEnabled(False)
        self.maxnumspin.setEnabled(False)
        self.delayspin.setEnabled(False)
        self.parallelismspin.setEnabled(False)
        #self.otherspin.setEnabled(False)
        self.progressBar.setReadOnly(True)


        self.retranslateUi(MainWindow)
        QtCore.QObject.connect(self.excludeip, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.excludeline.setEnabled)
        QtCore.QObject.connect(self.output, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.outputfor.setEnabled)
        QtCore.QObject.connect(self.timeout, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.timeoutspin.setEnabled )
        QtCore.QObject.connect(self.yourcommand, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.yourline.setEnabled)
        QtCore.QObject.connect(self.spoof, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.spoofline.setEnabled)
        QtCore.QObject.connect(self.fastscan, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.fastspin.setEnabled)
        QtCore.QObject.connect(self.maxhost, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.maxspin.setEnabled)
        QtCore.QObject.connect(self.fragment, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.fragmentspin.setEnabled)
        QtCore.QObject.connect(self.datalength, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.datalenspin.setEnabled)
        QtCore.QObject.connect(self.maxnumpacks, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.maxnumspin.setEnabled)
        QtCore.QObject.connect(self.delayscan, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.delayspin.setEnabled)
        QtCore.QObject.connect(self.parallelism, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.parallelismspin.setEnabled)
        QtCore.QObject.connect(self.defaultscan, QtCore.SIGNAL(_fromUtf8("clicked(bool)")), self.toggle)
        QtCore.QObject.connect(self.yourcommand, QtCore.SIGNAL(_fromUtf8("clicked()")), self.disable)
        QtCore.QObject.connect(self.actionAbout, QtCore.SIGNAL(_fromUtf8("activated()")), self.help)


        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):


        MainWindow.setWindowTitle(_translate("MainWindow", "Pymap Scanner", None))
        self.groupBox_4.setTitle(_translate("MainWindow", "Cursor", None))
        self.label_3.setText(_translate("MainWindow", ">", None))

        self.treeWidget.headerItem().setText(0, _translate("MainWindow", "Host/Port", None))
        self.treeWidget.headerItem().setText(1, _translate("MainWindow", "Status", None))
        self.treeWidget.headerItem().setText(2, _translate("MainWindow", "Services", None))

        self.outputfor.setItemText(0, _translate("MainWindow", "-XML-", None))
        self.outputfor.setItemText(1, _translate("MainWindow", "-HTML-", None))


        self.groupBox_5.setTitle(_translate("MainWindow", "Custom IP List", None))
        __sortingEnabled = self.customlist.isSortingEnabled()
        self.customlist.setSortingEnabled(False)

        self.customlist.setSortingEnabled(__sortingEnabled)
        self.getftp.setText(_translate("MainWindow", "Get FTP       >", None))
        self.getssh.setText(_translate("MainWindow", "Get SSH       >", None))
        self.getsmb.setText(_translate("MainWindow", "Get SMB      >", None))
        self.getrdp.setText(_translate("MainWindow", "Get RDP       >", None))
        self.getother.setText(_translate("MainWindow", "Get HTTP    >", None))
        #self.label_5.setText(_translate("MainWindow", "Other Port  >", None))



        self.groupBox_6.setTitle(_translate("MainWindow", "Options", None))
        self.yourline.setToolTip(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:8pt; font-weight:600; font-style:italic;\">Example: -n -sS -sV</span></p></body></html>", None))
        self.yourcommand.setText(_translate("MainWindow", "Your Command:", None))
        self.versionchck.setText(_translate("MainWindow", "Version Check", None))
        self.excludeip.setText(_translate("MainWindow", "Exclude Ip :", None))
        self.output.setText(_translate("MainWindow", "Output : ", None))
        self.excludeline.setToolTip(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:8pt; font-weight:600; font-style:italic;\">Example: 192.168.1.1</span></p></body></html>", None))
        self.justopen.setText(_translate("MainWindow", "Just Open Port", None))
        self.synscan.setText(_translate("MainWindow", "Syn Scan", None))
        self.defaultscan.setText(_translate("MainWindow", "Default Scan", None))
        self.allup.setText(_translate("MainWindow", "Os Detect", None))
        self.maxhost.setText(_translate("MainWindow", "Max Host :", None))
        self.fastscan.setText(_translate("MainWindow", "Fast Scan :", None))
        self.groupBox_7.setTitle(_translate("MainWindow", "Settings", None))
        self.openlist.setText(_translate("MainWindow", "Open List", None))
        self.port.setToolTip(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:8pt; font-style:italic;\">Example: 443,445,80</span></p></body></html>", None))
        self.label.setText(_translate("MainWindow", "Victim Ip/s:", None))
        self.porthelp.setToolTip(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:8pt; font-style:italic;\">Open Port Settings</span></p></body></html>", None))
        self.porthelp.setText(_translate("MainWindow", "?", None))
        self.label_4.setText(_translate("MainWindow", "Port/s:", None))
        self.hosthelp.setToolTip(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:8pt; font-style:italic;\">Open Victim Settings</span></p></body></html>", None))
        self.hosthelp.setText(_translate("MainWindow", "?", None))
        self.host.setToolTip(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:8pt; font-style:italic;\">Example : 192.168.1.2 192.168.1.0/24</span></p></body></html>", None))
        self.label_6.setText(_translate("MainWindow", "Status :", None))
        self.start.setText(_translate("MainWindow", "START SCAN", None))
        self.stop.setText(_translate("MainWindow", "STOP SCAN", None))
        self.reset.setText(_translate("MainWindow", "RESET ALL", None))
        self.groupBox_8.setTitle(_translate("MainWindow", "Advanced Options", None))
        self.parallelism.setText(_translate("MainWindow", "Parallelism :", None))
        self.timeout.setText(_translate("MainWindow", "Timeout :", None))
        self.delayscan.setText(_translate("MainWindow", "Delay Scan :", None))
        self.maxnumpacks.setText(_translate("MainWindow", "Max Num Packs :", None))
        self.randomscan.setText(_translate("MainWindow", "Aggressive", None))
        self.datalength.setText(_translate("MainWindow", "Data Length :", None))
        self.fragment.setText(_translate("MainWindow", "Packet Fragment :", None))
        self.spoofline.setToolTip(_translate("MainWindow", "<html><head/><body><p><span style=\" font-size:8pt;\">Example: google.com or Ip</span></p></body></html>", None))
        self.spoof.setText(_translate("MainWindow", "Spoof IP/s :", None))
        self.saveiplst.setText(_translate("MainWindow", "Save İp List", None))
        self.saveall.setText(_translate("MainWindow", "Save Output", None))
        self.savecvs.setText(_translate("MainWindow", "Save CVS", None))
        self.savecustomip.setText(_translate("MainWindow", "Save Custom IP", None))
        self.clearcustomip.setText(_translate("MainWindow", "Clear Custom IP", None))
        self.menuAbout.setTitle(_translate("MainWindow", "Help", None))
        self.actionAbout.setText(_translate("MainWindow", "About", None))


xslt = (os.popen("xsltproc")).read()
xnmap = (os.popen("nmap")).read()

if "Project libxslt" in xslt:
    if "SCAN TECHNIQUES:" in xnmap:
        app = QtGui.QApplication(sys.argv)
        app.setStyle('gtk+')
        win = Ui_MainWindow()
        cls = QtGui.QMainWindow()
        win.setupUi(cls)
        cls.show()
        sys.exit(app.exec_())

    else:
        print("Nmap Not Found ! Installed Please Wait..")
        print (os.system("apt-get -y install nmap"))
else:
    print("xsltproc Not Found ! Installed Please Wait..")
    print (os.system("apt-get -y install xsltproc"))

