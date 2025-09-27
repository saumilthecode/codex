
void FUN_0802a848(int param_1,int *param_2)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  int local_18;
  int *local_14;
  
  if (-1 < (int)((uint)*(ushort *)(param_2 + 3) << 0x1e)) {
    local_18 = param_1;
    local_14 = param_2;
    FUN_0802a800(param_1,param_2,&local_18,&local_14);
    iVar3 = local_18;
    iVar2 = FUN_08024a18(param_1,local_18);
    uVar1 = *(ushort *)(param_2 + 3);
    if (iVar2 != 0) {
      *(ushort *)(param_2 + 3) = uVar1 | 0x80;
      *param_2 = iVar2;
      param_2[4] = iVar2;
      param_2[5] = iVar3;
      if (local_14 == (int *)0x0) {
        return;
      }
      iVar3 = FUN_0802af58(param_1,(int)*(short *)((int)param_2 + 0xe));
      if (iVar3 == 0) {
        return;
      }
      *(ushort *)(param_2 + 3) = *(ushort *)(param_2 + 3) & 0xfffc | 1;
      return;
    }
    if ((int)(short)uVar1 << 0x16 < 0) {
      return;
    }
    *(ushort *)(param_2 + 3) = uVar1 & 0xfffc | 2;
  }
  *param_2 = (int)param_2 + 0x47;
  param_2[4] = (int)param_2 + 0x47;
  param_2[5] = 1;
  return;
}

