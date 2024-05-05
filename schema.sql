CREATE OR REPLACE USER `phpsessions`@`%` IDENTIFIED BY 'phpsessions';
create or replace database `phpsessions`;
GRANT SELECT, INSERT, UPDATE, LOCK TABLES, EXECUTE ON `phpsessions`.* TO `phpsessions`@`%`;
