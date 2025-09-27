
undefined4 *
FUN_0801e4f8(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,char param_7,undefined4 param_8,undefined4 param_9
            ,undefined4 param_10)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 uStack_1c;
  
  local_24 = DAT_0801e580;
  if (param_7 == '\0') {
    FUN_0801e06c(&local_20,param_2,param_3,param_4,param_5,param_6,param_8,param_9,&local_24);
  }
  else {
    FUN_0801dbe0(&local_20,param_2,param_3,param_4,param_5,param_6);
  }
  uVar2 = local_20;
  uVar1 = local_24;
  local_20 = FUN_08008940();
  FUN_0801f688(uVar1,param_10,param_9,&local_20);
  *param_1 = uVar2;
  param_1[1] = uStack_1c;
  FUN_08018950(local_24);
  return param_1;
}

