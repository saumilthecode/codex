
uint FUN_08020d42(undefined4 *param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  uint uVar4;
  
  pbVar3 = (byte *)*param_1;
  iVar2 = (int)param_1[1] - (int)pbVar3;
  if ((byte *)param_1[1] == pbVar3) {
    return 0xfffffffe;
  }
  uVar1 = (uint)*pbVar3;
  if (uVar1 < 0x80) {
    pbVar3 = pbVar3 + 1;
LAB_08020d56:
    *param_1 = pbVar3;
  }
  else {
    if (0xc1 < uVar1) {
      if (uVar1 < 0xe0) {
        if (iVar2 == 1) {
          return 0xfffffffe;
        }
        if ((pbVar3[1] & 0xc0) == 0x80) {
          uVar1 = (pbVar3[1] - 0x3080) + uVar1 * 0x40;
          if (param_2 < uVar1) {
            return uVar1;
          }
          pbVar3 = pbVar3 + 2;
          goto LAB_08020d56;
        }
      }
      else if (uVar1 < 0xf0) {
        if (iVar2 == 1) {
          return 0xfffffffe;
        }
        uVar4 = (uint)pbVar3[1];
        if ((uVar4 & 0xc0) == 0x80) {
          if (uVar1 == 0xe0) {
            if (0x9f < uVar4) {
LAB_08020da8:
              if (iVar2 == 2) {
                return 0xfffffffe;
              }
              if ((pbVar3[2] & 0xc0) == 0x80) {
                uVar1 = (pbVar3[2] - 0xe2080) + uVar1 * 0x1000 + uVar4 * 0x40;
                if (param_2 < uVar1) {
                  return uVar1;
                }
                pbVar3 = pbVar3 + 3;
                goto LAB_08020d56;
              }
            }
          }
          else if ((uVar1 != 0xed) || (uVar4 < 0xa0)) goto LAB_08020da8;
        }
      }
      else if ((uVar1 < 0xf5) && (0xffff < param_2)) {
        if (iVar2 == 1) {
          return 0xfffffffe;
        }
        uVar4 = (uint)pbVar3[1];
        if ((uVar4 & 0xc0) == 0x80) {
          if (uVar1 == 0xf0) {
            if (0x8f < uVar4) {
LAB_08020dec:
              if (iVar2 == 2) {
                return 0xfffffffe;
              }
              if ((pbVar3[2] & 0xc0) == 0x80) {
                if (iVar2 == 3) {
                  return 0xfffffffe;
                }
                if ((pbVar3[3] & 0xc0) == 0x80) {
                  uVar1 = pbVar3[3] + 0xfc37df80 + uVar1 * 0x40000 + uVar4 * 0x1000 +
                          (uint)pbVar3[2] * 0x40;
                  if (param_2 < uVar1) {
                    return uVar1;
                  }
                  pbVar3 = pbVar3 + 4;
                  goto LAB_08020d56;
                }
              }
            }
          }
          else if ((uVar1 != 0xf4) || (uVar4 < 0x90)) goto LAB_08020dec;
        }
      }
    }
    uVar1 = 0xffffffff;
  }
  return uVar1;
}

