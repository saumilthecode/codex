
undefined4 *
FUN_08016c64(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,char param_7,int param_8,undefined4 param_9,
            undefined4 *param_10)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int local_34;
  undefined4 local_30;
  undefined4 uStack_2c;
  
  uVar2 = FUN_0801126c(param_8 + 0x6c);
  local_34 = DAT_08016d08;
  if (param_7 == '\0') {
    FUN_08016750(&local_30,param_2,param_3,param_4,param_5,param_6,param_8,param_9,&local_34);
  }
  else {
    FUN_080162c8();
  }
  iVar3 = FUN_08010c1a(local_34);
  if (iVar3 != 0) {
    FUN_0800ac34(param_10,iVar3);
    iVar1 = local_34;
    iVar3 = iVar3 + local_34;
    FUN_0800a904(param_10);
    FUN_08010c84(uVar2,iVar1,iVar3,*param_10);
  }
  *param_1 = local_30;
  param_1[1] = uStack_2c;
  FUN_08010c74(local_34);
  return param_1;
}

