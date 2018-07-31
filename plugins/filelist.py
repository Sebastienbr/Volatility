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

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

class FileList(dumpfiles.DumpFiles):
    """List memory mapped files and cached files """

    def __init__(self, config, *args, **kwargs):
        dumpfiles.DumpFiles.__init__(self, config, *args, **kwargs)
        config.remove_option('DUMP-DIR')
        config.remove_option('SUMMARY-FILE')
        config.remove_option('NAME')
        self._config.DUMP_DIR = ""				

		
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Offset", "12"), ("PID", "5"), ("Present", "5"), ("Type", "20"), ("File Name", "95")])
        for summaryinfo in data:
			present = "Yes"
			if summaryinfo['type'] == "SharedCacheMap":
				if (len(summaryinfo['vacbary']) == 0):
					present = "No"				
			else:
				if (len(summaryinfo['present']) == 0):
					present = "No"
			self.table_row(outfd, "{0:#010x}".format(summaryinfo['fobj']), summaryinfo['pid'], present, summaryinfo['type'], summaryinfo['name'])	
			
    def unified_output(self, data):
        return TreeGrid([("Offset", Address),
                       ("PID", int),
                       ("Present", str),
                       ("Type", str),
                       ("File Name", str)],
                        self.generator(data))	
    
						
    def generator(self, data):
        for summaryinfo in data:
            present = "Yes"
            if summaryinfo['type'] == "SharedCacheMap":
                if (len(summaryinfo['vacbary']) == 0):
                    present = "No"				
            else:
                if (len(summaryinfo['present']) == 0):
                    present = "No"

            yield (0, [Address(summaryinfo['fobj']),
                       int(summaryinfo['pid']),
                       str(present),
                       str(summaryinfo['type']),
                       str(summaryinfo['name'])])		
