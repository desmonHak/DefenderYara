
rule Trojan_Win64_Filecoder_ARA_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c0 41 ff c0 6b c8 11 88 4c 14 30 48 ff c2 48 83 fa 10 7c d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}