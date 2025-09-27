
uint FUN_08017a22(int *param_1)

{
  uint uVar1;
  byte *pbVar2;
  bool bVar3;
  
  uVar1 = (**(code **)(*param_1 + 0x24))();
  pbVar2 = (byte *)(uVar1 + 1);
  bVar3 = pbVar2 != (byte *)0x0;
  if (bVar3) {
    pbVar2 = (byte *)param_1[2] + 1;
    uVar1 = (uint)*(byte *)param_1[2];
  }
  if (bVar3) {
    param_1[2] = (int)pbVar2;
  }
  return uVar1;
}

