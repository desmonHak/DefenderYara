
rule Trojan_Win64_CryptInject_CH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 0f b6 45 ?? 22 45 ?? f7 d0 21 d0 88 45 ?? 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 c2 0f b6 45 ?? 88 02 83 45 ?? 01 83 45 ?? 01 8b 45 ?? 48 98 48 3b 45 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}