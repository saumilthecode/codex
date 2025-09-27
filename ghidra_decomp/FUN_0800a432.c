
undefined4
FUN_0800a432(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 *param_6)

{
  undefined4 uVar1;
  undefined8 uVar2;
  undefined1 auStack_2c [24];
  undefined4 local_14;
  
  local_14 = 0;
  uVar1 = *param_6;
  uVar2 = FUN_0800914a(uVar1,*(undefined4 *)(param_2 + 0x10));
  FUN_0800c618(0,(int)((ulonglong)uVar2 >> 0x20),auStack_2c,param_3,param_4,param_5,uVar1,(int)uVar2
              );
  FUN_0800a2f0(param_1,auStack_2c);
  FUN_08009636(auStack_2c);
  return param_1;
}

