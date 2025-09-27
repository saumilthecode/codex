
int FUN_0802e638(undefined4 param_1,int param_2,int *param_3)

{
  int iVar1;
  char *pcVar2;
  char local_14 [4];
  
  iVar1 = FUN_08028508();
  if ((iVar1 == 1) && (param_2 - 1U < 0xff)) {
    local_14[0] = (char)param_2;
  }
  else {
    iVar1 = FUN_080258e8(param_1,local_14,param_2,param_3 + 0x17);
    if (iVar1 == -1) {
      *(ushort *)(param_3 + 3) = *(ushort *)(param_3 + 3) | 0x40;
      return -1;
    }
    if (iVar1 == 0) {
      return param_2;
    }
  }
  iVar1 = param_3[2] + -1;
  param_3[2] = iVar1;
  if ((iVar1 < 0) && ((iVar1 < param_3[6] || (local_14[0] == '\n')))) {
    iVar1 = FUN_0802f94c(param_1,local_14[0],param_3);
    if (iVar1 == -1) {
      return -1;
    }
  }
  else {
    pcVar2 = (char *)*param_3;
    *param_3 = (int)(pcVar2 + 1);
    *pcVar2 = local_14[0];
  }
  return param_2;
}

