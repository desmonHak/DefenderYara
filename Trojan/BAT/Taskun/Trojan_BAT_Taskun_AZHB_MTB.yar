
rule Trojan_BAT_Taskun_AZHB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AZHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 61 0a 02 7b ?? 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 03 6f ?? 00 00 0a 0b 02 7b ?? 00 00 04 7b ?? 00 00 04 16 5f 0c 19 8d ?? 00 00 01 0d 09 16 12 01 28 ?? 00 00 0a 9c 09 17 12 01 28 ?? 00 00 0a 9c 09 18 12 01 28 ?? 00 00 0a 9c 19 8d ?? 00 00 01 25 16 09 08 19 5d 91 9c 25 17 09 17 08 58 19 5d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}