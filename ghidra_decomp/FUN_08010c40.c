
void FUN_08010c40(undefined4 *param_1,int param_2,uint param_3)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined8 uVar4;
  
  uVar3 = *param_1;
  uVar1 = FUN_08010c20(uVar3,param_2,DAT_08010c70);
  uVar4 = FUN_08010c1a(uVar3,uVar1);
  uVar2 = (int)uVar4 - param_2;
  if (param_3 <= uVar2) {
    uVar2 = param_3;
  }
  FUN_0800a844(param_1,(int)((ulonglong)uVar4 >> 0x20),uVar2,0);
  return;
}

