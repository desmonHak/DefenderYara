
rule Trojan_Win32_SuspProxi_F{
	meta:
		description = "Trojan:Win32/SuspProxi.F,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {77 6c 72 6d 64 72 2e 65 78 65 20 } //wlrmdr.exe   1
		$a_80_1 = {2d 73 20 30 20 2d 66 20 30 20 2d 74 20 30 20 2d 6d 20 30 20 2d 61 20 31 31 20 2d 75 } //-s 0 -f 0 -t 0 -m 0 -a 11 -u  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}