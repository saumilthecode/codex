
undefined4 *
FUN_08024800(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,char param_7,int param_8,undefined4 param_9,
            undefined4 *param_10)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_48;
  undefined4 uStack_44;
  undefined1 *local_40;
  int local_3c;
  undefined1 local_38 [20];
  
  uVar2 = FUN_0801126c(param_8 + 0x6c);
  local_40 = local_38;
  local_3c = 0;
  local_38[0] = 0;
  if (param_7 == '\0') {
    FUN_080242f4(&local_48,param_2,param_3,param_4,param_5,param_6,param_8,param_9,&local_40);
  }
  else {
    FUN_08023e78();
  }
  iVar1 = local_3c;
  if (local_3c != 0) {
    FUN_08017fbe(param_10,local_3c);
    FUN_08021e08(uVar2,local_40,local_40 + iVar1,*param_10);
  }
  *param_1 = local_48;
  param_1[1] = uStack_44;
  FUN_08006cec(&local_40);
  return param_1;
}

