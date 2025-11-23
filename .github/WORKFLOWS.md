# Dev

- Branch code
- Test using `.dev` cfg and `dev_mode = ".dev"`
- Add stuff where-ever
- Update docs
- Reflect changes test some edge cases

## Adding Commands

1. Create `z/<command>.py`
2. Add command to regex in `terces` dispatcher
3. Reuse from `gnilux`:
   - `U2FKey` - auth + key derivation
   - `CFG` - config values
   - `_success`, `_error`, `_debug` - output
   - `_random` - secure random bytes
4. Use `auth.get_terces(salt)` for key derivation
5. Salt pattern: `key_handle + identifier` for credential binding
