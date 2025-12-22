
rule Trojan_Win64_AsyncRAT_PGAR_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.PGAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c1 49 f7 e0 48 c1 ea 02 48 8d 04 52 48 03 c0 49 8b c8 48 2b c8 42 0f b6 [0-06] 42 30 04 07 49 ff c0 4c 3b ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}