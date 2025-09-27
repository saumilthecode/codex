
undefined4 FUN_0800b54c(int param_1,byte param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  byte *pbVar3;
  
  pbVar3 = (byte *)(param_1 + 0x48f);
  puVar2 = (undefined4 *)(param_1 + 0x4a0);
  while ((pbVar3 = pbVar3 + 1, (param_2 & *pbVar3) == 0 ||
         (iVar1 = FUN_080259b4(param_3,*puVar2), iVar1 == 0))) {
    puVar2 = puVar2 + 1;
    if (pbVar3 == (byte *)(param_1 + 0x497)) {
      return 0;
    }
  }
  return 1;
}

