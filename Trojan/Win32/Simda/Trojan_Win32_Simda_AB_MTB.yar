
rule Trojan_Win32_Simda_AB_MTB{
	meta:
		description = "Trojan:Win32/Simda.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 87 c6 03 ee 4e 45 83 cd 17 4e 03 eb 48 43 03 fb 4f 48 2b f8 66 09 f6 8b ca 03 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}