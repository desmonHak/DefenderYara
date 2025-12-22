
rule Trojan_Win32_LummaStealer_RPR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPR!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 70 00 6f 00 6c 00 69 00 63 00 79 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 6e 00 65 00 77 00 2d 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 6e 00 61 00 6d 00 65 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 62 00 69 00 6e 00 61 00 72 00 79 00 70 00 61 00 74 00 68 00 6e 00 61 00 6d 00 65 00 } //10 -executionpolicy bypass -command new-service -name downloaderservice -binarypathname
		$a_00_1 = {2d 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 74 00 79 00 70 00 65 00 20 00 61 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 63 00 } //1 -startuptype automatic
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}