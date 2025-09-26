In order to be able to decompile the said programme properly. Remember to set the type when decompiling to C src for inspection to x64 ARM little endian Cortex. After setting up ghidra and launching the .bin file for decompilation, you will need to wait for awhile to ensure everything has been decompiled. This programme is basically a STM32 baremetal application and requires the STM32 emulator located inside the same .tar.xz as the csit_iot.bin binary. Your task is to:
> identify ALL commands + operands thats accepted by the application to allow for manipulation of values. (other than just slot)
> Get a comprehensive detailed inspection on the csit_iot.bin to be able to determine the rough structure of the application.
> Reconnanise any particularly interesting functions / data.

What we know now:
> the application parses commands in JSON, so you cant just invoke a command without curly braces. One syntax i found out is {"slot": 1} which in the distribution source code produces a array [84,73,83,67,123,70,65,75,69,95,70,76,65,71,95,71,79,69,83,95,72,69,82,69,125,0,0,0,0,0,0,0] TISC{FAKE_FLAG_GOES_HERE}, however when accessing this in the actual production server, we are greeted with slots 1-15 bearing "dummy" values, which are phrases. Therefore, i am NOT seeking for just finding the flag via slot, but instead enact a recon stage in order to determine which syntaxes are allowed. Furthermore, FUN_00007260 has the programme's code for checking "slot", however you may need to dig deeper in order to find more syntaxes. If you need to, please download any tools such as pwntools or objdump in order to recon properly. You also are able to search up certain steps, however do be informed that no available writeups of this challenge exists as of now. Also, it would be great if you could manage to spin up the local docker-compose.yml so that you can test ur theories / payloads locally.
> i also suspect a heap overflow exploit in this challenge, and that it might be exploitable. HOWEVER, you should be free and open to change of ideas,  just find the solve and continue. To consider this challenge as solved, you will need to invoke the contents of index 0, ie TISC{REAL_FLAG_GOES_HERE} IS the winning flag we are supposed to be accessing.
> Earlier today, i found out that you can do two things. {"slot": X, "data": array} to be checking the contents of the said slot against your provided data array, and {"slot": X} only to view the contents of said slot X.
> run challenge locally to test! (or u can just nc whatever)
__Challenge Information_

HWisntThatHardv2
TISC
LEVEL 9
description
Last year many brave agents showed the world what they could do against PALINDROME's custom TPM chips. Their actions sent chills down the spines of all those who seek to do us harm. This year, we managed to exfiltrate an entire STM32-based system and its firmware from within SPECTRE.

Since you probably do not have STM32 development boards at home, we have built an emulator that does its best to emulate the STM32 chip and its peripherals. This is neatly packaged inside a docker container, so you can run it on your own machine.

Your mission, if you choose to accept it, is to find out what this device is built to do, how to interact with it, and, if possible, how to exploit it.

You will be provided with the following emulator + firmware:
- MD5 (HWisntThatHard_v2.tar.xz) = 1246c6248e2788613f702a50d162b748
- MD5 (config.yaml) = 5ea0a99dc870dd3ae31370e69c652002
- MD5 (csit_iot.bin) = 57a8e159e6d81e620f618258cd4f4a50
- MD5 (docker-compose.yml) = e284296706c38121e6074cfd09f0a062
- MD5 (Dockerfile) = 84ee422322a23d6e25e73d3a44e59763
- MD5 (ext-flash.bin) = 8ea3bc31ef48ec78012c0c46d857f50e
- MD5 (stm32-emulator) = 731c0d36f8949bd8a5f26ee05b821b8c
- MD5 (stm32f407.svd) = cd5687242c32a448d84e6995065ddaf1


You can perform your attack on a live STM32 module hosted behind enemy lines:
nc chals.tisc25.ctf.sg 51728 [Not needed to hit the main prod server yet, we are still reconning.]

attached files
HWisntThatHard_v2.tar.xz < attached to the conversation as a file>
____________
ANALYSIS_REPORT.md has ALL the starting information for you to build on
/dist has the entire tar.xz uncompressed into files
PLEASE use analyzeHeadless in GHIDRA (once you done downloading it) and use -processor ARM:LE:32:Cortex to analyze csit_iot.bin [Optional: DUMP the entire folder of decompiled C files once youre done and wrapping up to the pull request]
Furthermore, download pwntools to interact with the netcat of the localhost OR challenge server. I HIGHLY recommend you to take a look at the decompiled files by huge chunks (view 200+ lines at a single time) and do static analysis + theory first since you WILL cover more ground, and leverage ANALYSIS_REPORT.md for fundementals of the app and to build on it (or find another exploit i dunno). Once you are confident with the static analysis + theory, you can start enumerating payloads. THIS challenge has no time limit, and you are not pressured to exit in less than 1 hour and you are encourage to spend ALOT of time on this. Please also note that you can also leverage online writeups AND research papers AND information online [HIGHLY RECOMMENDED TO ENSURE YOU GET YOUR FACTS RIGHT] so yeah u can also do that. 
> I ALSO PACKED THE ENTIRE csit_iot.bin DECOMPILED FUNCTIONS INTO ghidra_decomp.zip attached to this chat. So no need for ghidra to be downloaded.
[09:36, 19/09/2025] .: Furthermore, the entry point of the programme I believe is located in "FUN_08007260.c", so once you view that file, you can branch out to another functions to get the bigger picture. This way you can actually understand it. However, I have a big suspicion that heap exploitation (over by one) is exploitable but I'm not sure due to live bytes will be switched every time you NC into the instance, and when you do ann unsucessful overflow attempt which does not yield a return 2, the connection WILL close.
[09:37, 19/09/2025] .: I also believe exponentation and scientific notaiton  bypasses are most likely not the solve, as this has a pwn related element to it, therefore we have to exploit something. Please also focus mainly on static analysis for this one, and spin up the docker compose if you are HIGHLY confident that you have found the exploit.

FURTHERMORE, PLEASE utilize angr to be able to debug locally, its quite good and supports the STM32 arch that the .bin loads. PLEASE TEST YOUR SCRIPT AGAINST A LOCAL INSTANCE BY INITATING A docker compose up AND ONCE YOU ARE CONFIDENT YOU CAN GET TO PRINT THE FLAG (located in the first row of ext-flash.bin) PLEASE SEND THE FULL COMPLETE SCRIPT [that uses pwntools of course] AS WELL AS THE WRITEUP.