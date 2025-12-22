
rule Ransom_Win32_Crypmodng_GXX_MTB{
	meta:
		description = "Ransom:Win32/Crypmodng.GXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 00 61 00 6b 00 65 00 46 00 69 00 6c 00 65 00 31 00 2e 00 74 00 78 00 74 00 } //1 FakeFile1.txt
		$a_01_1 = {4d 61 6c 54 65 73 74 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}