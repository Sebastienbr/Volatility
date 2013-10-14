# Volatility
#
# Authors:
# Sebastien Bourdon-Richard
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


import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.conf as conf
import sys, urllib, copy, os		
			
			
class VMEMAddressSpace(addrspace.AbstractRunBasedMemory):
    """ This AS supports the VMEM format with VMSN/VMSS metadata """
    
    order = 30
    vmem_address_space = True 
	
			  
    def __init__(self, base, config, **kwargs):

		
        ## We must have an AS below us
        self.as_assert(base, "No base Address Space")
        addrspace.AbstractRunBasedMemory.__init__(self, base, config, **kwargs)
		
		## Avoid infinite loop (not sure if it's the best way to do that...)
        self.as_assert(not (hasattr(base, 'vmem_address_space') and base.vmem_address_space), "Can not stack over another vmem")
        self.as_assert(not (hasattr(base, 'paging_address_space') and base.paging_address_space), "Can not stack over another paging address space")

		## Check if there's vmem metadata
        self.as_assert(config.VM_METADATA, 'No vmware metadata specified')
		
        ## This is a tuple of (physical memory offset, file offset, length)
        self.runs = []
		
		## Check if there's vmem metadata
        self.as_assert(config.VM_METADATA.startswith("file://"), 'Location is not of file scheme')
		
		## Second AS for VMSN/VMSS manipulation
        self.as_assert(config.LOCATION is not config.VM_METADATA, 'Vm metadata file')		
        vmMetaConfig = copy.deepcopy(config)
        vmMetaConfig.LOCATION = vmMetaConfig.VM_METADATA
        vmMetaConfig.VM_METADATA = None
        vmMetaAddressSpace = utils.load_as(vmMetaConfig, astype = 'physical')
		
		## The number of memory regions contained in the file 
        self.region_count = vmMetaAddressSpace._get_tag(grp_name = "memory", tag_name = "regionsCount", data_type = "unsigned int")
				
        if self.region_count.is_valid() and self.region_count != 0:

            ## Create multiple runs - one for each region in the header
			## Code from vmware.py
            for i in range(self.region_count):

                memory_offset = vmMetaAddressSpace._get_tag(grp_name = "memory", tag_name = "regionPPN",
                                indices = [i],
                                data_type = "unsigned int") * vmMetaAddressSpace.PAGE_SIZE

                file_offset = vmMetaAddressSpace._get_tag(grp_name = "memory",
                                tag_name = "regionPageNum", indices = [i],
                                data_type = "unsigned int") * vmMetaAddressSpace.PAGE_SIZE
								
                length = vmMetaAddressSpace._get_tag(grp_name = "memory", tag_name = "regionSize",
                                indices = [i],
                                data_type = "unsigned int") * vmMetaAddressSpace.PAGE_SIZE
								
                self.runs.append((memory_offset, file_offset, length))

        else:
            self.as_assert(False, 'Region count is not valid or 0')		
			
				
        ## Make sure we found at least one memory run
        self.as_assert(len(self.runs) > 0, "Cannot find any memory run information")

		
    def set_vmware_metadata_location(_option, _opt_str, value, parser):
        """Sets the location variable in the parser to the filename in question"""
        if not os.path.exists(os.path.abspath(value)):
            debug.error("The requested file doesn't exist")
        if parser.values.vm_metadata == None:
            slashes = "//"
            # Windows pathname2url decides to convert C:\blah to ///C:/blah
            # So to keep the URLs correct, we only add file: rather than file://
            if sys.platform.startswith('win'):
                slashes = ""
            parser.values.vm_metadata = "file:" + slashes + urllib.pathname2url(os.path.abspath(value))
			
			
    #Add the --vm_metadata option
    config = conf.ConfObject()
    config.add_option("VM_METADATA", default = None, action = "callback",
                  callback = set_vmware_metadata_location, type = 'str',
                  nargs = 1,
                  help = "Vmware metadata (i.e: vmss/vmsn file) to pad the vmem file in the address space")