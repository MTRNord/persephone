#pragma once
#include "drogon/drogon.h"

class Migrator {
public:
  void migrate() const;

private:
  void migration_v0() const;
  void migration_v1() const;
  void migration_v2() const;
  void migration_v3() const;
};
