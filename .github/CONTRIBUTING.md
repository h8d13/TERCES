# Dev

- Fork the repo
- Branch code
- Test using `.dev` cfg and `dev_mode = ".dev"`
- Add stuff where-ever, remove comments from cfg file
- Update docs
- Reflect changes test some edge cases

## Adding Commands

1. Create `z/<command>.py`
2. Add command to regex in `terces` dispatcher
3. Reuse from `gnilux` what you need:
   - `U2FKey` - auth + key derivation
   - `CFG` - config values
   - `_success`, `_error`, `_debug` - output 
4. Or the others...

See usage in other `z/` commands for reference and write some tests if you're feeling fancy.
Or better yet test manually with some on-purpose errors.

---

Have fun and test with a keys that you don't mind bricking :D And do send a PR !