#pragma once

class Migrator {
public:
  static void migrate();

private:
  static void migration_v0();
  static void migration_v1();
  static void migration_v2();
  static void migration_v3();
  static void migration_v4();
  static void migration_v5();
  static void migration_v6();
};
