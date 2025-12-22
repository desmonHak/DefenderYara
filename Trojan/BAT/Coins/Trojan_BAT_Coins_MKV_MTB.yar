
rule Trojan_BAT_Coins_MKV_MTB{
	meta:
		description = "Trojan:BAT/Coins.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 03 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a 08 17 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 07 16 07 8e 69 6f ?? 00 00 0a 13 04 de 1f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}