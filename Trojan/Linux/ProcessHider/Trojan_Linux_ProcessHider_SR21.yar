
rule Trojan_Linux_ProcessHider_SR21{
	meta:
		description = "Trojan:Linux/ProcessHider.SR21,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 73 00 6d 00 6f 00 64 00 20 00 } //2 insmod 
		$a_00_1 = {72 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 2e 00 6b 00 6f 00 } //10 rootkit.ko
		$a_00_2 = {64 00 69 00 61 00 6d 00 6f 00 72 00 70 00 68 00 69 00 6e 00 65 00 2e 00 6b 00 6f 00 } //10 diamorphine.ko
		$a_00_3 = {72 00 74 00 6b 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6b 00 6f 00 } //10 rtkkeylogger.ko
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=12
 
}