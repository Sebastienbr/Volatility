VMware VMEM address space
----------------------------

This is a vmem address space for Volatility. If the memory allocated for the virtual machine is more than 3.5GB (approx.), you need to supply a vmss file to volatility in order to analyze the memory dump.

Example on how to use it:

	python vol.py -f memory.vmem --vm_metadata=metadata.vmss pslist

