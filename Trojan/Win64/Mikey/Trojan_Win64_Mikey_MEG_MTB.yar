
rule Trojan_Win64_Mikey_MEG_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b df 48 8d 14 39 4c 8b c6 4c 2b c1 66 66 0f 1f 84 00 00 00 00 00 0f b6 04 1a 48 8d 52 ?? 34 fb 88 42 ff 49 83 e8 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}