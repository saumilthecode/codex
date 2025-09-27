
undefined4 *
FUN_0800a3ac(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined1 param_7,undefined4 param_8,int *param_9
            ,undefined4 param_10)

{
  undefined4 local_50;
  undefined4 uStack_4c;
  undefined4 local_48;
  undefined4 local_44;
  int local_3c;
  undefined4 local_38;
  undefined1 auStack_34 [24];
  undefined4 local_1c;
  
  local_1c = 0;
  local_3c = 0;
  local_48 = param_3;
  local_44 = param_4;
  FUN_0800c834(&local_50,0,*(undefined4 *)(param_2 + 8),param_3,param_4,param_5,param_6,param_7,
               param_8,&local_3c,0,auStack_34);
  local_48 = local_50;
  local_44 = uStack_4c;
  if (local_3c == 0) {
    FUN_0800a2f0(&local_38,auStack_34);
    FUN_0800a6fc(param_10,&local_38);
    FUN_080091fc(local_38);
  }
  else {
    *param_9 = local_3c;
  }
  *param_1 = local_48;
  param_1[1] = local_44;
  FUN_08009636(auStack_34);
  return param_1;
}

