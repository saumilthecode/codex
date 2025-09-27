
undefined4
FUN_080213c0(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,undefined1 param_5)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined4 local_20;
  undefined4 uStack_1c;
  uint uStack_18;
  
  local_20 = param_1;
  uStack_1c = param_2;
  uStack_18 = param_3;
  FUN_08021240(&local_20,param_5);
  uVar3 = 0;
  while( true ) {
    uVar2 = uVar3 + 1;
    if (param_3 <= uVar2) {
      if (uVar2 == param_3) {
        uVar3 = 0xffff;
        if (param_4 < 0x10000) {
          uVar3 = param_4;
        }
        FUN_08020d42(&local_20,uVar3);
      }
      return local_20;
    }
    uVar1 = FUN_08020d42(&local_20,param_4);
    if (param_4 < uVar1) break;
    if (uVar1 < 0x10000) {
      uVar2 = uVar3;
    }
    uVar3 = uVar2 + 1;
  }
  return local_20;
}

