
rule Trojan_Win32_Amadey_AB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f7 83 e7 1f 0f b6 1c 39 30 1c 32 8d 7e 01 83 e7 1f 0f b6 1c 39 30 5c 32 01 83 c6 02 39 f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}