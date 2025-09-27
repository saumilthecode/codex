
uint FUN_0802e4f4(undefined4 param_1,int *param_2)

{
  byte bVar1;
  int iVar2;
  undefined4 *puVar3;
  byte *pbVar4;
  uint local_14;
  
  if ((0 < param_2[1]) || (iVar2 = FUN_080261d0(), iVar2 == 0)) {
    iVar2 = FUN_08028508();
    if (iVar2 == 1) {
      pbVar4 = (byte *)*param_2;
      *param_2 = (int)(pbVar4 + 1);
      bVar1 = *pbVar4;
      param_2[1] = param_2[1] + -1;
      return (uint)bVar1;
    }
    do {
      iVar2 = FUN_08025898(param_1,&local_14,*param_2,param_2[1],param_2 + 0x17);
      if (iVar2 == -1) break;
      if (iVar2 != -2) {
        if (iVar2 != 0) {
          *param_2 = *param_2 + iVar2;
          param_2[1] = param_2[1] - iVar2;
          return local_14;
        }
        *param_2 = *param_2 + 1;
        param_2[1] = param_2[1] + -1;
        return 0;
      }
      iVar2 = FUN_080261d0(param_1,param_2);
    } while (iVar2 == 0);
    *(ushort *)(param_2 + 3) = *(ushort *)(param_2 + 3) | 0x40;
    puVar3 = (undefined4 *)FUN_080285f8();
    *puVar3 = 0x8a;
  }
  return 0xffffffff;
}

