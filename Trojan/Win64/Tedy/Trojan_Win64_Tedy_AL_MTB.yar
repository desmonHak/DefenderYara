
rule Trojan_Win64_Tedy_AL_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 8b f1 49 8b d8 4c 8b e2 48 8b f9 45 33 ed 48 8b 49 10 48 be fe ff ff ff ff ff ff 7f 48 8b c6 48 2b c1 48 83 f8 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}