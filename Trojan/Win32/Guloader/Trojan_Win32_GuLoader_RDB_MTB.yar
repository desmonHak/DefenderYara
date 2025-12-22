
rule Trojan_Win32_GuLoader_RDB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6a 6f 68 61 6e 6e 61 73 20 61 66 66 65 64 74 6e 69 6e 67 65 72 6e 65 73 20 6c 69 6e 67 61 6d 73 } //1 johannas affedtningernes lingams
		$a_81_1 = {61 72 67 75 6d 65 6e 74 61 74 69 6f 6e 20 63 6f 6d 70 6c 69 61 62 6c 65 } //1 argumentation compliable
		$a_81_2 = {75 66 6f 72 73 69 67 74 69 67 68 65 64 65 72 73 20 6c 75 66 62 65 72 72 79 2e 65 78 65 } //1 uforsigtigheders lufberry.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}