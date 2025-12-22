
rule Trojan_Win32_Crypt_SXB_MTB{
	meta:
		description = "Trojan:Win32/Crypt.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 b0 99 f7 f9 8b 55 ac 2b d0 89 55 ac c7 45 a4 ?? ?? ?? ?? 8b 4d a4 83 c1 ?? 8b 45 ac 99 } //3
		$a_03_1 = {8b 4d 84 03 01 03 45 98 89 45 98 c7 45 b4 ?? ?? ?? ?? 8b 55 b4 0f af 55 b4 0f af 55 9c 89 55 9c c7 45 9c ?? ?? ?? ?? 81 7d 9c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}