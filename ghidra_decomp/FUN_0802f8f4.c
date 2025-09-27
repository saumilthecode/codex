
int FUN_0802f8f4(undefined4 param_1,undefined4 param_2,int *param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = param_3[2];
  if (iVar1 != 0) {
    iVar3 = *param_3 + 8;
    do {
      while( true ) {
        iVar2 = param_3[1];
        param_3[1] = iVar2 + -1;
        if (iVar2 < 1) goto LAB_0802f940;
        iVar2 = *(int *)(iVar3 + -4);
        if (iVar2 == 0) break;
        iVar1 = FUN_08029bc0(param_1,param_2,*(undefined4 *)(iVar3 + -8),iVar2 << 2,param_4);
        if (iVar1 == -1) goto LAB_0802f942;
        iVar1 = param_3[2] - iVar2;
        param_3[2] = iVar1;
        iVar3 = iVar3 + 8;
        if (iVar1 == 0) goto LAB_0802f940;
      }
      iVar3 = iVar3 + 8;
    } while (iVar1 != 0);
  }
LAB_0802f940:
  iVar1 = 0;
LAB_0802f942:
  param_3[1] = 0;
  param_3[2] = 0;
  return iVar1;
}

