
rule Trojan_Win64_ValleyRAT_BA_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 ff c0 89 44 24 20 83 7c 24 20 40 ?? ?? 48 63 44 24 20 0f b6 44 04 50 83 f0 ?? 48 63 4c 24 20 88 44 0c 50 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 83 f0 5c 48 63 4c 24 20 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}