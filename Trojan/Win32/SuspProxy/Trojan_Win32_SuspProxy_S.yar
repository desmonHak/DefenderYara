
rule Trojan_Win32_SuspProxy_S{
	meta:
		description = "Trojan:Win32/SuspProxy.S,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {74 70 6d 74 6f 6f 6c } //tpmtool  1
		$a_80_1 = {64 72 69 76 65 72 74 72 61 63 69 6e 67 } //drivertracing  1
		$a_80_2 = {73 74 6f 70 } //stop  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}