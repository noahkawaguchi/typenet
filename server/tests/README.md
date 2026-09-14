This directory only contains this crate's top-level integration tests. Most of the crate's tests are in `src` along with the code they test.

These tests in particular must run as their own processes because they mutate process-wide state, so they are written as integration tests with one test per file.
