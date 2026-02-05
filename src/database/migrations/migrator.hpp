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
  static void migration_v7();
  static void migration_v8();
  static void migration_v9();
  static void migration_v10();
  static void migration_v11();
  static void migration_v12();
  static void migration_v13();
};
