-- Dhakefile.dhall — build fx-core's docs site with dhake.
--
--    ./vendor/dhake/dhake.com                       # default: dist/index.html (+ all pages)
--    ./vendor/dhake/dhake.com dist/index.html       # the command reference
--
--   The site is an MFE (@mfe/framework) app whose content is NOT hand-written: it
--   is derived from `docs/commands.json`, which `zig build docs` generates from the
--   Dhall schemas.  So a command added to its schema gains a page here with no
--   other edit.
--
--   Pipeline:
--     1. zig build docs                -> docs/commands.json   (from schemas/)
--     2. node scripts/gen-shell.mjs    -> shell/pages.js + shell/templates/<slot>.html
--     3. node scripts/copy-mfe.mjs     -> vendor/@mfe/{core,framework}   (built framework)
--     4. elm make site/Main.elm        -> dist/elm.js
--     5. node scripts/ssg.mjs          -> dist/index.html + dist/<name>/index.html (+ shell/)

let Action =
      < Shell : Text
      | Copy : { from : Text, to : Text }
      | Mkdir : < Plain : Text | Parents : { path : Text, parents : Bool } >
      | Rm : < Plain : Text | Recursive : { path : Text, recursive : Bool } >
      | Touch : Text
      | Move : { from : Text, to : Text }
      | Symlink : { from : Text, to : Text }
      | Chmod : { path : Text, mode : Text }
      | Echo : Text
      | Env : { key : Text, value : Text }
      | Run : { argv : List Text }
      >

let Target = { deps : List Text, phony : Bool, recipe : List Action }

in  { targets =
        [ -- the command dataset, generated from the Dhall schemas.  phony: its
          -- inputs are the whole schemas/ dir, and regenerating is cheap and
          -- deterministic (the zig step is itself a no-op when current).
          { mapKey = "docs/commands.json"
          , mapValue =
              { deps = [ "schemas" ]
              , phony = True
              , recipe = [ < Shell = "zig build docs" > ]
              }
          }
          -- the MFE shell artifacts, derived from the dataset.
        , { mapKey = "shell-pages"
          , mapValue =
              { deps = [ "docs/commands.json", "scripts/gen-shell.mjs" ]
              , phony = True
              , recipe = [ < Shell = "node scripts/gen-shell.mjs" > ]
              }
          }
          -- the built @mfe framework, staged under vendor/@mfe.  phony: the
          -- build output lives inside the mfe-framework submodule
          -- (packages/*/dist), not at a stable top-level path.
        , { mapKey = "vendor-mfe"
          , mapValue =
              { deps = []
              , phony = True
              , recipe =
                  [ < Shell =
                        "( cd vendor/mfe-framework && npm ci --no-audit --no-fund && npm run build )"
                    >
                  , < Shell = "node scripts/copy-mfe.mjs" >
                  ]
              }
          }
        , { mapKey = "dist/elm.js"
          , mapValue =
              { deps = [ "site/Main.elm", "elm.json", "vendor/design/src" ]
              , phony = False
              , recipe =
                  -- elm is a vendored ELF at node_modules/elm/bin/elm; a plain
                  -- dhake Shell action does not get node_modules/.bin on PATH,
                  -- so use the real path.
                  [ < Shell = "mkdir -p dist" >
                  , < Shell =
                        "node_modules/elm/bin/elm make site/Main.elm --output=dist/elm.js --optimize"
                    >
                  ]
              }
          }
        , { mapKey = "dist/index.html"
          , mapValue =
              { deps =
                  [ "dist/elm.js"
                  , "shell-pages"
                  , "vendor-mfe"
                  , "shell/shell.js"
                  , "shell/mfe/fx-core-page.js"
                  , "scripts/ssg.mjs"
                  ]
              , phony = False
              , recipe = [ < Shell = "node scripts/ssg.mjs" > ]
              }
          }
        ]
      , default = "dist/index.html"
      }
