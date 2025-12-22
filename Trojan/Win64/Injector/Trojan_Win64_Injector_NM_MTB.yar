
rule Trojan_Win64_Injector_NM_MTB{
	meta:
		description = "Trojan:Win64/Injector.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 42 e5 09 00 bf 01 00 00 00 ?? b8 e0 f9 ff 48 85 db 76 5c 48 89 44 ?? 28 48 c7 44 ?? 20 00 00 00 00 48 8b 54 ?? 28 48 89 54 ?? 20 48 8b 05 ac 83 1a 00 48 8d 5c ?? 20 b9 01 00 00 00 48 89 cf ?? e2 76 fb ff 66 } //2
		$a_03_1 = {48 8d 05 62 f4 08 00 66 ?? ?? 3b 08 f6 ff 48 8b 8c ?? a8 00 00 00 48 89 48 08 48 8b 8c ?? b0 00 00 00 48 89 48 10 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}