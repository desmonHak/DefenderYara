
rule Trojan_Win64_Rozena_ADMB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.ADMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 8d 0c 06 33 d2 49 8b c0 49 f7 f2 42 0f b6 04 22 32 04 19 88 01 49 ff c0 4c 3b c7 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}