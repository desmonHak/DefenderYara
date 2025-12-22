
rule Backdoor_Linux_Mirai_LR_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LR!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 2b 78 20 75 70 6e 70 3b 20 2e 2f 75 70 6e 70 3b 20 2e 2f 2e 66 66 64 66 64 20 73 65 6c 66 72 65 70 2e 65 63 68 6f } //1 /bin/busybox chmod +x upnp; ./upnp; ./.ffdfd selfrep.echo
		$a_01_1 = {66 74 70 67 65 74 2e 73 68 20 66 74 70 67 65 74 2e 73 68 20 26 26 20 73 68 20 66 74 70 67 65 74 2e 73 68 3b 63 75 72 6c 20 68 74 74 70 3a 2f 2f } //1 ftpget.sh ftpget.sh && sh ftpget.sh;curl http://
		$a_01_2 = {2f 77 67 65 74 2e 73 68 20 2d 4f 2d 20 7c 20 73 68 3b 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 67 } //1 /wget.sh -O- | sh;/bin/busybox tftp -g
		$a_01_3 = {2d 72 20 74 66 74 70 2e 73 68 20 2d 6c 2d 20 7c 20 73 68 3b 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 66 74 70 67 65 74 } //1 -r tftp.sh -l- | sh;/bin/busybox ftpget
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}