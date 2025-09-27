
undefined4 * FUN_0800b588(int param_1,undefined4 *param_2,undefined4 *param_3,byte *param_4)

{
  int iVar1;
  byte bVar2;
  undefined4 *puVar3;
  byte *pbVar4;
  
  for (; param_2 < param_3; param_2 = param_2 + 1) {
    puVar3 = (undefined4 *)(param_1 + 0x49c);
    pbVar4 = (byte *)(param_1 + 0x490);
    bVar2 = 0;
    do {
      puVar3 = puVar3 + 1;
      iVar1 = FUN_080259b4(*param_2,*puVar3);
      if (iVar1 != 0) {
        bVar2 = bVar2 | *pbVar4;
      }
      pbVar4 = pbVar4 + 1;
    } while (puVar3 != (undefined4 *)(param_1 + 0x4bc));
    *param_4 = bVar2;
    param_4 = param_4 + 1;
  }
  return param_3;
}

