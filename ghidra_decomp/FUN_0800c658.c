
void FUN_0800c658(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,int param_7,int param_8)

{
  int extraout_r1;
  undefined1 *local_48 [2];
  undefined1 auStack_40 [16];
  undefined1 auStack_30 [28];
  
  local_48[0] = auStack_40;
  if ((param_7 == 0) && (param_8 != 0)) {
    FUN_080104fc(DAT_0800c6ac);
    param_7 = extraout_r1;
  }
  FUN_0800bc20(local_48,param_7,param_7 + param_8 * 4);
  FUN_0800e062(auStack_30,param_2,param_4,param_5,param_6,local_48);
  FUN_0800bd1c(param_3,auStack_30);
  FUN_0801e9cc(auStack_30);
  FUN_0801e9cc(local_48);
  return;
}

