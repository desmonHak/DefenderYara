
rule Trojan_Win32_GuLoader_RCM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6d 61 6c 69 68 69 6e 69 73 20 70 72 79 64 65 6c 73 65 72 20 70 6c 65 75 72 6f 63 65 6e 74 72 61 6c } //1 malihinis prydelser pleurocentral
		$a_81_1 = {6b 6f 6e 73 74 72 75 6b 74 69 6f 6e 73 6d 61 61 64 65 6e } //1 konstruktionsmaaden
		$a_81_2 = {73 65 6a 72 73 } //1 sejrs
		$a_81_3 = {61 72 65 61 6c 62 65 72 65 67 6e 69 6e 67 65 72 6e 65 20 6b 6e 6c 65 64 64 65 74 2e 65 78 65 } //1 arealberegningerne knleddet.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}