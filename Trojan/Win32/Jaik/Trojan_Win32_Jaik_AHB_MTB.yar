
rule Trojan_Win32_Jaik_AHB_MTB{
	meta:
		description = "Trojan:Win32/Jaik.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c8 c1 e0 ?? 31 c1 89 d0 c1 f8 ?? 89 cb 31 d0 c1 fb ?? 31 c8 8d 8d 20 ff ff ff 31 c3 } //30
		$a_03_1 = {ff 0f a4 c2 ?? c1 e0 ?? 29 c6 8b 45 10 19 d7 99 8b 85 e4 fe ff ff 0f af c2 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}