
rule Trojan_Win64_Vidar_XTP_MTB{
	meta:
		description = "Trojan:Win64/Vidar.XTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 f8 48 8d 52 01 0f b6 4c 3c 50 41 8d 04 08 44 0f b6 c0 42 0f b6 44 04 50 88 44 3c 50 42 88 4c 04 50 0f b6 44 3c ?? 03 c1 0f b6 c0 0f b6 4c 04 50 30 4a ff 49 83 e9 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}