
undefined4
FUN_08012e20(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5
            ,undefined4 param_6,undefined4 param_7,char param_8,char param_9)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined1 local_a4;
  char local_a3;
  char local_a2;
  undefined1 local_a1;
  undefined1 auStack_a0 [132];
  
  uVar1 = FUN_0801126c(param_5 + 0x6c);
  uVar2 = FUN_0801146c(param_5 + 0x6c);
  local_a4 = FUN_08010ce2(uVar1,0x25);
  if (param_9 == '\0') {
    local_a3 = param_8;
    local_a2 = param_9;
  }
  else {
    local_a1 = 0;
    local_a3 = param_9;
    local_a2 = param_8;
  }
  FUN_080207da(uVar2,auStack_a0,0x80,&local_a4,param_7);
  uVar1 = FUN_08005ea0(auStack_a0);
  FUN_08011c98(param_1,param_3,param_4,auStack_a0,uVar1);
  return param_1;
}

