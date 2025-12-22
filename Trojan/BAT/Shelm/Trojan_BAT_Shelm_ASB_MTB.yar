
rule Trojan_BAT_Shelm_ASB_MTB{
	meta:
		description = "Trojan:BAT/Shelm.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 07 11 19 07 11 19 91 20 fa 00 00 00 61 d2 9c 00 11 19 17 58 13 19 11 19 07 8e 69 fe 04 13 1a 11 1a 2d dc } //3
		$a_80_1 = {53 65 63 74 69 6f 6e 73 20 53 68 65 6c 6c 63 6f 64 65 20 50 72 6f 63 65 73 73 20 49 6e 6a 65 63 74 6f 72 } //Sections Shellcode Process Injector  1
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
	condition:
		((#a_01_0  & 1)*3+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}