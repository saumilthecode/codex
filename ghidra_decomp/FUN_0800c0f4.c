
undefined4
FUN_0800c0f4(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined1 param_5
            ,undefined4 param_6,undefined1 param_7,int *param_8)

{
  undefined1 *local_2c [2];
  undefined1 auStack_24 [16];
  undefined4 local_14;
  
  local_14 = 0;
  local_2c[0] = auStack_24;
  FUN_0800bc9c(local_2c,*param_8,param_8[1] + *param_8);
  local_14 = DAT_0800c158;
  FUN_0800a318(param_1,0,*(undefined4 *)(param_2 + 8),param_3,param_4,param_5,param_6,param_7,0,0,
               local_2c);
  FUN_08009636(local_2c);
  return param_1;
}

