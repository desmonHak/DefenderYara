
rule Trojan_BAT_Taskun_ZKN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 19 5d 13 1e 19 8d ?? 00 00 01 13 1f 11 1f 16 12 18 28 ?? 00 00 0a 9c 11 1f 17 12 18 28 ?? 00 00 0a 9c 11 1f 18 12 18 28 ?? 00 00 0a 9c 11 1a 16 fe 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}