
/* WARNING: Control flow encountered bad instruction data */

int FUN_080001ac(int param_1,int *param_2)

{
  char *pcVar1;
  uint uVar2;
  char *pcVar3;
  int *piVar4;
  int iVar5;
  char cStack_31;
  char local_30 [36];
  
  FUN_08028666(local_30,*param_2,param_2[1] - *param_2);
  piVar4 = piRam0800022c;
  iVar5 = 0;
  pcVar1 = (char *)(param_1 + -1);
  pcVar3 = &cStack_31;
  do {
    pcVar3 = pcVar3 + 1;
    pcVar1 = pcVar1 + 1;
    if (*pcVar3 == *pcVar1) {
      iVar5 = iVar5 + 1;
    }
  } while (local_30 + 0x1f != pcVar3);
  FUN_080178c4(piRam0800022c,DAT_08000230,0xc);
  piVar4 = *(int **)((int)piVar4 + *(int *)(*piVar4 + -0xc) + 0x7c);
  if (piVar4 != (int *)0x0) {
    if ((char)piVar4[7] == '\0') {
      FUN_0800b34a(piVar4);
      uVar2 = 10;
      if (*(code **)(*piVar4 + 0x18) != DAT_08000234) {
        uVar2 = (**(code **)(*piVar4 + 0x18))(piVar4,10);
      }
    }
    else {
      uVar2 = (uint)*(byte *)((int)piVar4 + 0x27);
    }
    FUN_08017740(piRam0800022c,uVar2);
    FUN_080176b6();
    return iVar5;
  }
  FUN_080104f6();
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

