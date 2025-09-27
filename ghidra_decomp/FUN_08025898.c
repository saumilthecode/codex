
void FUN_08025898(undefined4 *param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 *param_5)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = param_2;
  iVar1 = param_3;
  if (param_3 == 0) {
    param_4 = 1;
    uVar2 = 0;
    iVar1 = DAT_080258c8;
  }
  iVar1 = (**(code **)(DAT_080258c4 + 0xe4))(param_1,uVar2,iVar1,param_4,param_5,param_2,param_3);
  if (iVar1 == -1) {
    *param_5 = 0;
    *param_1 = 0x8a;
  }
  return;
}

