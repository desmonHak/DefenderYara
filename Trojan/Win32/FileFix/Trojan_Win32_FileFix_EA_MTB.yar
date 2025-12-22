
rule Trojan_Win32_FileFix_EA_MTB{
	meta:
		description = "Trojan:Win32/FileFix.EA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,73 00 73 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 Powershell
		$a_00_1 = {3d 00 27 00 78 00 79 00 7a 00 27 00 3b 00 } //10 ='xyz';
		$a_00_2 = {20 00 23 00 20 00 } //5  # 
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*5) >=115
 
}