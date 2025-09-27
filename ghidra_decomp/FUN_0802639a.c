
void FUN_0802639a(undefined4 param_1,int param_2)

{
  int iVar1;
  ushort uVar2;
  bool bVar3;
  
  iVar1 = FUN_08028544(param_1,(int)*(short *)(param_2 + 0xe));
  bVar3 = iVar1 == -1;
  if (bVar3) {
    uVar2 = *(ushort *)(param_2 + 0xc) & 0xefff;
  }
  else {
    uVar2 = *(ushort *)(param_2 + 0xc) | 0x1000;
  }
  if (bVar3) {
    *(ushort *)(param_2 + 0xc) = uVar2;
  }
  if (!bVar3) {
    *(ushort *)(param_2 + 0xc) = uVar2;
  }
  if (!bVar3) {
    *(int *)(param_2 + 0x54) = iVar1;
  }
  return;
}

