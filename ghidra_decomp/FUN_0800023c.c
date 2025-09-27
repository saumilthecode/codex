
/* WARNING: Control flow encountered bad instruction data */

undefined4 FUN_0800023c(void)

{
  undefined4 uVar1;
  int *piVar2;
  uint uVar3;
  int *piVar4;
  
  uVar1 = thunk_FUN_080001ac();
  FUN_080178c4(DAT_080002a0,DAT_0800029c,8);
  piVar2 = (int *)FUN_0801796c(DAT_080002a0,uVar1);
  piVar4 = *(int **)((int)piVar2 + *(int *)(*piVar2 + -0xc) + 0x7c);
  if (piVar4 != (int *)0x0) {
    if ((char)piVar4[7] == '\0') {
      FUN_0800b34a(piVar4);
      uVar3 = 10;
      if (*(code **)(*piVar4 + 0x18) != DAT_080002a4) {
        uVar3 = (**(code **)(*piVar4 + 0x18))(piVar4,10);
      }
    }
    else {
      uVar3 = (uint)*(byte *)((int)piVar4 + 0x27);
    }
    FUN_08017740(piVar2,uVar3);
    FUN_080176b6();
    return uVar1;
  }
  FUN_080104f6();
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

