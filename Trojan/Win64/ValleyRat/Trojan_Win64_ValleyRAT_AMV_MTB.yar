
rule Trojan_Win64_ValleyRAT_AMV_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.AMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c8 49 f7 e0 49 8b c0 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 41 30 04 18 49 ff c0 4c 3b c5 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}