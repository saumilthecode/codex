
undefined4 * FUN_08028f6c(int param_1,uint param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0x1c);
  if (puVar4 == (undefined4 *)0x0) {
    puVar4 = (undefined4 *)FUN_080249b4(0x10);
    *(undefined4 **)(param_1 + 0x1c) = puVar4;
    puVar1 = puVar4;
    if (puVar4 == (undefined4 *)0x0) {
      puVar1 = (undefined4 *)FUN_08028754(DAT_08028fe4,0x6b,0,DAT_08028fe0);
    }
    puVar1[1] = 0;
    puVar1[2] = 0;
    *puVar1 = 0;
    puVar1[3] = 0;
  }
  iVar3 = puVar4[3];
  if (iVar3 == 0) {
    uVar2 = FUN_0802af78(param_1,4,0x21);
    iVar3 = *(int *)(param_1 + 0x1c);
    puVar4[3] = uVar2;
    iVar3 = *(int *)(iVar3 + 0xc);
    if (iVar3 != 0) goto LAB_08028fb2;
LAB_08028fae:
    puVar4 = (undefined4 *)0x0;
  }
  else {
LAB_08028fb2:
    puVar4 = *(undefined4 **)(iVar3 + param_2 * 4);
    if (puVar4 == (undefined4 *)0x0) {
      iVar3 = 1 << (param_2 & 0xff);
      puVar4 = (undefined4 *)FUN_0802af78(param_1,1,(iVar3 + 5) * 4);
      if (puVar4 == (undefined4 *)0x0) goto LAB_08028fae;
      puVar4[1] = param_2;
      puVar4[2] = iVar3;
    }
    else {
      *(undefined4 *)(iVar3 + param_2 * 4) = *puVar4;
    }
    puVar4[3] = 0;
    puVar4[4] = 0;
  }
  return puVar4;
}

