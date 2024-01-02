#pragma once
#include "drogon/drogon.h"

class Migrator {
public:
  void migrate();

private:
  void migration_v0();
  void migration_v1();
  void migration_v2();
  void migration_v3();
};
