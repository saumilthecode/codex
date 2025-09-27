
undefined4 *
FUN_08024770(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,char param_7,undefined4 param_8,undefined4 param_9
            ,undefined4 param_10)

{
  undefined4 uVar1;
  undefined1 *puVar2;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined1 *local_38;
  undefined4 local_34;
  undefined1 local_30 [20];
  
  local_38 = local_30;
  local_34 = 0;
  local_30[0] = 0;
  if (param_7 == '\0') {
    FUN_080242f4(&local_40,param_2,param_3,param_4,param_5,param_6,param_8,param_9,&local_38);
  }
  else {
    FUN_08023e78(&local_40,param_2,param_3,param_4,param_5,param_6);
  }
  puVar2 = local_38;
  uVar1 = local_40;
  local_40 = FUN_08008940();
  FUN_0801f688(puVar2,param_10,param_9,&local_40);
  *param_1 = uVar1;
  param_1[1] = uStack_3c;
  FUN_08006cec(&local_38);
  return param_1;
}

