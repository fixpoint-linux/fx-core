-- Dhakefile.dhall — build fx-core's docs site with dhake.
--
--    ./vendor/dhake/dhake.com                       # default target: dist/index.html
--    ./vendor/dhake/dhake.com dist/index.html       # the command reference
--
--   The site is an Elm app (site/Main.elm) rendered against the shared
--   Fixpoint.* design package (the `design` submodule at vendor/design).  Its
--   content is NOT hand-written: it is derived from `docs/commands.json`, which
--   `zig build docs` generates from the Dhall schemas, and passed to the Elm app
--   as flags by scripts/ssg.mjs.
--
--   Pipeline:
--     1. zig build docs                       -> docs/commands.json
--     2. elm make site/Main.elm               -> dist/elm.js
--     3. node scripts/ssg.mjs                 -> dist/index.html (SSG pre-render)

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
        [ -- the command dataset, generated from the Dhall schemas.  phony:
          -- its inputs are the whole schemas/ dir, and regenerating is cheap
          -- and deterministic (the zig build step is itself a no-op when
          -- current).
          { mapKey = "docs/commands.json"
          , mapValue =
              { deps = [ "schemas" ]
              , phony = True
              , recipe = [ < Shell = "zig build docs" > ]
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
        , { mapKey = "index.html"
          , mapValue =
              { deps =
                  [ "dist/elm.js"
                  , "docs/commands.json"
                  , "shell/index.html"
                  , "scripts/ssg.mjs"
                  ]
              , phony = False
              , recipe = [ < Shell = "node scripts/ssg.mjs" > ]
              }
          }
        ]
      , default = "index.html"
      }
