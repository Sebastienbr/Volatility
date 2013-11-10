# Volatility
#
# Author:
# Sebastien Bourdon-Richard 
#
# This code is based on dumpfiles plugin. Thanks to AAron and the Volatility team. 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Sebastien Bourdon-Richard
@license:      GNU General Public License 2.0 or later
"""

import volatility.plugins.common as common 
import volatility.plugins.dumpfiles as dumpfiles
import volatility.debug as debug
import hashlib, json, urllib, urllib2, time, io, httplib, mimetypes

#--------------------------------------------------------------------------------
# Constants
#--------------------------------------------------------------------------------

VT_API_KEY = '<----------------PASTE VIRUSTOTAL API KEY HERE---------------->'
VT_URL_REPORT = "https://www.virustotal.com/vtapi/v2/file/report"
VT_URL_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan"
VT_NUMBER_OF_RETRY = 4  #Number of retry when sending a file to VT (0=No wait, 1= One minute wait...)

#Src: http://code.activestate.com/recipes/146306/
class postfile:
    @staticmethod
    def post_multipart(host, selector, fields, files):
        """
        Post fields and files to an http host as multipart/form-data.
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files
        Return the server's response page.
        """
        content_type, body = postfile.encode_multipart_formdata(fields, files)
        h = httplib.HTTPS(host)
        h.putrequest('POST', selector)
        h.putheader('content-type', content_type)
        h.putheader('content-length', str(len(body)))
        h.endheaders()
        h.send(body)
        errcode, errmsg, headers = h.getreply()
    
        return h.file.read()

    @staticmethod
    def encode_multipart_formdata(fields, files):
        """
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files
        Return (content_type, body) ready for httplib.HTTP instance
        """
        BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
        CRLF = '\r\n'
        L = []
        for (key, value) in fields:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        for (key, filename, value) in files:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-Type: %s' % postfile.get_content_type(filename))
            L.append('')
            L.append(value)
        L.append('--' + BOUNDARY + '--')
        L.append('')
        body = CRLF.join((bytes(i) for i in L))
        content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
        
        return content_type, body

    @staticmethod
    def get_content_type(filename):
        return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
		
		
class VirusTotal(dumpfiles.DumpFiles):
    """
    Query and submit memory mapped/cached files to VirusTotal.
    Please edit virustotal.py to enter your VirusTotal API key
    """

    def __init__(self, config, *args, **kwargs):
        dumpfiles.DumpFiles.__init__(self, config, *args, **kwargs)
        config.remove_option('DUMP-DIR')
        config.remove_option('SUMMARY-FILE')
        config.remove_option('NAME')
        config.add_option('SUBMIT', short_option = 'S', default = False, 
                      help = 'Send files to VirusTotal for scanning. Default is false. If this option is not selected, nothing is sent to VT.',
                      action = 'store_true')
        config.add_option('DELAY', short_option = 'D', default = 16, 
                      help='Delay in seconds between VT queries. Default value is 16 seconds (public VT API is limited to 4 requests per minute).',
					  action = 'store')
        self._config.DUMP_DIR = "" 	#DumpFiles plugin verify if DUMP_DIR is not None

		
    def virusTotalQuery(self, md5):	
        """	Query md5 on VirusTotal	"""
		#Query delay
        time.sleep(self._config.DELAY)
        parameters = {"resource": md5, "apikey": VT_API_KEY}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(VT_URL_REPORT, data)
        response = urllib2.urlopen(req)
        jsonResponse = response.read()
        return json.loads(jsonResponse)
	
	
    def virusTotalScan(self, fileName, file_to_send):	
		"""	Scan file on VirusTotal	"""	
		#Scan delay	
		time.sleep(self._config.DELAY)
		host = "www.virustotal.com"
		fields = [("apikey", VT_API_KEY)]
		files = [("file", fileName, file_to_send)]
		jsonScan = postfile.post_multipart(host, VT_URL_SCAN, fields, files)
		return json.loads(jsonScan)	
	
	
    def virusTotalAnalysis(self, md5, summaryinfo, outfd, file_to_send):
        # Write information about the cached file	
        outfd.write("************************************************************************\n")
        outfd.write("File: "+ summaryinfo['name'] + "\n")	
        outfd.write("Cache file type: " + 	summaryinfo['type'] + "\n")	
        outfd.write("PID: {0:<6}\n".format(summaryinfo['pid']))
        outfd.write("MD5: " + md5 + "\n")
		
        # Retrieving file scan report 
        try:
			vtJsonQuery =  self.virusTotalQuery(md5)
		
			# File is not on VT
			if vtJsonQuery['response_code'] == 0:
			
				# Send file to VT if option is selected
				if (self._config.SUBMIT):
				
					outfd.write("File not present on VirusTotal. Uploading file...\n")	
					# Send file to VT
					vtJsonScan = self.virusTotalScan("Volatility-" + md5, file_to_send)

					# If the file is correctly sent
					if vtJsonScan['response_code'] == 1:
						outfd.write(vtJsonScan['verbose_msg'] + "\n")
						
						# Retrieving file scan report again 
						vtJsonQuery = self.virusTotalQuery(vtJsonScan['md5'])
						
						# Files sent using the API have the lowest scanning priority. Depending on VirusTotal's load, 
						# it may take several hours before the file is scanned. Waiting maximum 4 minutes to get the results.
						retry = 0
						while vtJsonQuery['response_code'] == 0 or vtJsonQuery['response_code'] == -2:
							if retry < VT_NUMBER_OF_RETRY:
								outfd.write("Requested item is still queued for analysis...waiting 60 seconds\n")
								time.sleep(60)
								vtJsonQuery = self.virusTotalQuery(vtJsonScan['md5'])
							else:
								outfd.write("Requested item is still not present on VT. Please try again later.\n")
								break
							retry += 1
					else:
						outfd.write("Error submitting file to VirusTotal\n")	
						
				# File is not present on VT
				else:
					outfd.write("File not present on VirusTotal\n")
					return
				
			# File is still queued
			elif vtJsonQuery['response_code'] == -2:
				outfd.write("Requested item is still queued for analysis\n")
			
			# Show the file scan report 
			if vtJsonQuery['response_code'] == 1:
				outfd.write("Detection ratio: " + str(vtJsonQuery['positives']) + "/" + str(vtJsonQuery['total']) + "\n")
				outfd.write("Analysis date: " +	vtJsonQuery['scan_date'] + "\n\n")
				if (vtJsonQuery['positives'] > 0):
					self.table_header(outfd, [("Antivirus", "25"), ("Result", "40"), ("Update", "12")])
					for av in vtJsonQuery['scans']:
						result = "None"
						if (vtJsonQuery['scans'][av]['detected']):
							result = vtJsonQuery['scans'][av]['result']
						self.table_row(outfd, av, result, vtJsonQuery['scans'][av]['update'])					
					
        except Exception, err:
			debug.error(str(err))
			pass

			
	# Src: Code modified from the dumpfiles plugin		
    def render_text(self, outfd, data):
        if VT_API_KEY == '<----------------PASTE VIRUSTOTAL API KEY HERE---------------->':
            debug.error("Please edit virustotal.py and paste your VirusTotal API KEY")
        for summaryinfo in data:

            if summaryinfo['type'] == "DataSectionObject":

                if len(summaryinfo['present']) == 0:
                    continue

                tmpFile = io.BytesIO()
                sig = hashlib.md5()
                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue
                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                    if not rdata:
                        continue

                    tmpFile.seek(mdata[1])
                    tmpFile.write(rdata)
                    continue

                sig.update(tmpFile.getvalue())
                self.virusTotalAnalysis(sig.hexdigest(), summaryinfo, outfd, tmpFile.getvalue())
                tmpFile.close()


            elif summaryinfo['type'] == "ImageSectionObject":

                if len(summaryinfo['present']) == 0:
                    continue

                tmpFile = io.BytesIO()
                sig = hashlib.md5()
                for mdata in summaryinfo['present']:
                    rdata = None
                    if not mdata[0]:
                        continue

                    try:
                        rdata = self.kaddr_space.base.read(mdata[0], mdata[2])
                    except (IOError, OverflowError):
                        debug.debug("IOError: Pid: {0} File: {1} PhysAddr: {2} Size: {3}".format(summaryinfo['pid'], summaryinfo['name'], mdata[0], mdata[2]))

                    if not rdata:
                        continue

                    tmpFile.seek(mdata[1])
                    tmpFile.write(rdata)
                    continue

                sig.update(tmpFile.getvalue())
                self.virusTotalAnalysis(sig.hexdigest(), summaryinfo, outfd, tmpFile.getvalue())
                tmpFile.close()

            elif summaryinfo['type'] == "SharedCacheMap":

                tmpFile = io.BytesIO()				
                sig = hashlib.md5()
                for vacb in summaryinfo['vacbary']:
                    if not vacb:
                        continue
                    (rdata, mdata, zpad) = self.audited_read_bytes(self.kaddr_space, vacb['baseaddr'], vacb['size'], True)
                    ### We need to update the mdata,zpad
                    if rdata:
                        try:
                            tmpFile.seek(vacb['foffset'])
                            tmpFile.write(rdata)
                        except IOError:
                            # TODO: Handle things like write errors (not enough disk space, etc)
                            continue
                    vacb['present'] = mdata
                    vacb['pad'] = zpad

                sig.update(tmpFile.getvalue())
                self.virusTotalAnalysis(sig.hexdigest(), summaryinfo, outfd, tmpFile.getvalue())
                tmpFile.close()
				
            else:
                return


		
