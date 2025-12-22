
rule Trojan_Win32_Lazy_MB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e0 03 0f b6 80 ?? ?? ?? ?? 66 33 44 4c 60 66 89 84 4c ?? ?? ?? ?? 41 83 f9 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}