
rule Tampering_Win32_SuspWerFaultSec_A{
	meta:
		description = "Tampering:Win32/SuspWerFaultSec.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {20 00 2f 00 70 00 69 00 64 00 20 00 } //1  /pid 
		$a_00_1 = {57 00 65 00 72 00 46 00 61 00 75 00 6c 00 74 00 53 00 65 00 63 00 75 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //1 WerFaultSecure.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}