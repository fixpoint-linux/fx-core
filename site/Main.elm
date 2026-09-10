module Main exposing (main)

{-| The fx-core command reference — a static page listing every command, its
description, usage line, and its arguments (field, type, default, flags,
positional). All content is derived from `docs/commands.json`, which is
generated from the Dhall schemas (`zig build docs`), and arrives as Elm flags.

No hand-written per-command prose lives here: the schema is the source of truth,
so the reference cannot drift from the actual CLI.
-}

import Browser
import Css
import Fixpoint.Nav
import Fixpoint.Style as Style
import Html
import Html.Styled as Styled exposing (Html)
import Html.Styled.Attributes as Attr exposing (css, href)
import Json.Decode as D


main : Program D.Value Model Msg
main =
    Browser.element
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        }


type alias Command =
    { name : String
    , doc : String
    , usage : String
    , args : List Arg
    , mutex : List (List String)
    }


type alias Arg =
    { field : String
    , type_ : String
    , default : String
    , positional : Maybe Positional
    , flags : List Flag
    }


type alias Positional =
    { display : String
    , many : Bool
    }


type alias Flag =
    { short : Maybe String
    , long : Maybe String
    , kind : String
    , value : Maybe String
    }


type alias Model =
    { commands : List Command
    , error : Maybe String
    }


type Msg
    = NoOp


init : D.Value -> ( Model, Cmd Msg )
init flags =
    case D.decodeValue commandsDecoder flags of
        Ok cmds ->
            ( { commands = cmds, error = Nothing }, Cmd.none )

        Err err ->
            ( { commands = [], error = Just (D.errorToString err) }, Cmd.none )


update : Msg -> Model -> ( Model, Cmd Msg )
update _ model =
    ( model, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none


commandsDecoder : D.Decoder (List Command)
commandsDecoder =
    D.field "commands" (D.list commandDecoder)


commandDecoder : D.Decoder Command
commandDecoder =
    D.map5 Command
        (D.field "name" D.string)
        (D.field "doc" D.string)
        (D.field "usage" D.string)
        (D.field "args" (D.list argDecoder))
        (D.field "mutually_exclusive" (D.list (D.list D.string)))


argDecoder : D.Decoder Arg
argDecoder =
    D.map5 Arg
        (D.field "field" D.string)
        (D.field "type" D.string)
        (D.field "default" D.string)
        (D.field "positional" (D.nullable positionalDecoder))
        (D.field "flags" (D.list flagDecoder))


positionalDecoder : D.Decoder Positional
positionalDecoder =
    D.map2 Positional
        (D.field "display" D.string)
        (D.field "many" D.bool)


flagDecoder : D.Decoder Flag
flagDecoder =
    D.map4 Flag
        (D.field "short" (D.nullable D.string))
        (D.field "long" (D.nullable D.string))
        (D.field "kind" D.string)
        (D.field "value" (D.nullable D.string))



-- VIEW


view : Model -> Html.Html Msg
view model =
    Styled.toUnstyled <|
        Styled.div []
            [ Style.stylesheet
            , Fixpoint.Nav.view
                { brand = Styled.text "fx-core"
                , links =
                    [ Fixpoint.Nav.link "https://fixpointlinux.org" "fixpoint-linux.org"
                    , Fixpoint.Nav.link "https://github.com/fixpoint-linux/fx-core" "github"
                    ]
                , extra = []
                }
            , Styled.main_ [ css [ Style.wrap, mainS ] ]
                [ header
                , case model.error of
                    Just err ->
                        Styled.p [ css [ errorS ] ] [ Styled.text ("could not read commands.json: " ++ err) ]

                    Nothing ->
                        Styled.div [] (List.map commandSection model.commands)
                ]
            , footer
            ]


header : Html msg
header =
    Styled.div [ css [ introS ] ]
        [ Styled.h1 [] [ Styled.text "Command reference" ]
        , Styled.p []
            [ Styled.text "Every "
            , Styled.code [] [ Styled.text "fx-" ]
            , Styled.text " command, generated from its Dhall schema. The schema is the single source of truth: the same declaration produces the POSIX parser, the typed Dhall-record form, and this page."
            ]
        , Styled.p []
            [ Styled.text "See "
            , linkInline "https://github.com/fixpoint-linux/fx-core/blob/main/README.md" "the README"
            , Styled.text " for how to add a command, or "
            , linkInline "https://github.com/fixpoint-linux/fx-core/blob/main/concept.md" "concept.md"
            , Styled.text " for the design."
            ]
        ]


commandSection : Command -> Html msg
commandSection cmd =
    Styled.section [ css [ cmdS ], Attr.id cmd.name ]
        [ Styled.h2 [ css [ cmdHeadS ] ]
            [ Styled.code [ css [ cmdNameS ] ] [ Styled.text ("fx-" ++ cmd.name) ]
            , Styled.span [ css [ docS ] ] [ Styled.text cmd.doc ]
            ]
        , Styled.p [ css [ usageS ] ] [ Styled.code [] [ Styled.text cmd.usage ] ]
        , if List.isEmpty cmd.args then
            Styled.p [ css [ mutedS ] ] [ Styled.text "No arguments." ]

          else
            argsTable cmd.args
        , mutexNote cmd.mutex
        ]


argsTable : List Arg -> Html msg
argsTable args =
    Styled.table [ css [ tableS ] ]
        [ Styled.thead []
            [ Styled.tr []
                (List.map (\h -> Styled.th [ css [ thS ] ] [ Styled.text h ])
                    [ "field", "type", "default", "flag / operand" ]
                )
            ]
        , Styled.tbody [] (List.map argRow args)
        ]


{-| One row per argument: the field, its type, its default, and its CLI
surface — every flag that binds it (annotated with the operand it takes, for
a Value flag), or, for a positional field, the operand's display name.
-}
argRow : Arg -> Html msg
argRow arg =
    Styled.tr []
        [ Styled.td [ css [ tdS, fieldS ] ] [ Styled.code [] [ Styled.text arg.field ] ]
        , Styled.td [ css [ tdS, typeS ] ] [ Styled.code [] [ Styled.text arg.type_ ] ]
        , Styled.td [ css [ tdS, defaultS ] ] [ Styled.code [] [ Styled.text arg.default ] ]
        , Styled.td [ css [ tdS ] ]
            [ case ( arg.flags, arg.positional ) of
                ( [], Just p ) ->
                    Styled.code [ css [ operandS ] ]
                        [ Styled.text
                            (if p.many then
                                p.display ++ " …"

                             else
                                p.display
                            )
                        ]

                ( [], Nothing ) ->
                    Styled.span [ css [ noneS ] ] [ Styled.text "config only" ]

                ( flags, _ ) ->
                    Styled.span [] (List.indexedMap (flagSpan arg) flags)
            ]
        ]


{-| Render one flag binding: `-l, --long`, or for a Value flag
`-n, --lines <N>` so the reader sees it consumes an operand.
-}
flagSpan : Arg -> Int -> Flag -> Html msg
flagSpan arg i f =
    Styled.span []
        [ if i > 0 then
            Styled.text "  "

          else
            Styled.text ""
        , Styled.code [ css [ flagS ] ] [ Styled.text (flagTokens f) ]
        , if f.kind == "Value" then
            Styled.span [ css [ operandS ] ]
                [ Styled.text (" " ++ valuePlaceholder arg.type_) ]

          else
            Styled.text ""
        ]


{-| A readable placeholder for a Value flag's operand, from the field type.
-}
valuePlaceholder : String -> String
valuePlaceholder type_ =
    if String.contains "Natural" type_ || String.contains "Integer" type_ || String.contains "Double" type_ then
        "N"

    else
        "TEXT"


flagTokens : Flag -> String
flagTokens f =
    String.join ", " (List.filterMap identity [ f.short, f.long ])


mutexNote : List (List String) -> Html msg
mutexNote groups =
    if List.isEmpty groups then
        Styled.text ""

    else
        Styled.p [ css [ mutexS ] ]
            [ Styled.text "Mutually exclusive: "
            , Styled.text (String.join "  |  " (List.map (String.join " ") groups))
            ]


footer : Html msg
footer =
    Styled.footer [ css [ footerS ] ]
        [ Styled.text "Generated from the Dhall schemas. Part of "
        , linkInline "https://github.com/fixpoint-linux" "fixpoint-linux"
        , Styled.text "."
        ]


linkInline : String -> String -> Html msg
linkInline url label =
    Styled.a [ href url ] [ Styled.text label ]


thCell : String -> String
thCell s =
    s



-- STYLES (layout only; colours/fonts come from Fixpoint.Style)


mainS : Css.Style
mainS =
    Css.paddingTop (Css.px 40)


introS : Css.Style
introS =
    Css.marginBottom (Css.px 40)


errorS : Css.Style
errorS =
    Css.batch [ Css.color (Css.hex "ff7b72"), Css.fontFamilies Style.fontMono ]


cmdS : Css.Style
cmdS =
    Css.batch
        [ Css.paddingTop (Css.px 28)
        , Css.marginTop (Css.px 8)
        , Css.borderTop3 (Css.px 1) Css.solid Style.line
        ]


cmdHeadS : Css.Style
cmdHeadS =
    Css.batch
        [ Css.displayFlex
        , Css.alignItems Css.baseline
        , Css.property "gap" "12px"
        , Css.flexWrap Css.wrap
        , Css.marginBottom (Css.px 10)
        ]


cmdNameS : Css.Style
cmdNameS =
    Css.batch
        [ Css.fontFamilies Style.fontMono
        , Css.fontSize (Css.px 19)
        , Css.color Style.accent
        , Css.fontWeight (Css.int 600)
        ]


docS : Css.Style
docS =
    Css.batch
        [ Css.color Style.fg
        , Css.fontSize (Css.px 14)
        , Css.fontWeight (Css.int 400)
        ]


usageS : Css.Style
usageS =
    Css.batch
        [ Css.color Style.dim
        , Css.fontSize (Css.px 13)
        , Css.marginBottom (Css.px 12)
        ]


mutedS : Css.Style
mutedS =
    Css.batch [ Css.color Style.dim, Css.fontSize (Css.px 13) ]


tableS : Css.Style
tableS =
    Css.batch
        [ Css.width (Css.pct 100)
        , Css.borderCollapse Css.collapse
        , Css.fontSize (Css.px 12)
        , Css.marginBottom (Css.px 6)
        ]


thS : Css.Style
thS =
    Css.batch
        [ Css.textAlign Css.left
        , Css.fontFamilies Style.fontMono
        , Css.fontSize (Css.px 11)
        , Css.color Style.dim
        , Css.fontWeight (Css.int 500)
        , Css.padding2 (Css.px 4) (Css.px 10)
        , Css.borderBottom3 (Css.px 1) Css.solid Style.line
        ]


tdS : Css.Style
tdS =
    Css.batch
        [ Css.padding2 (Css.px 5) (Css.px 10)
        , Css.borderBottom3 (Css.px 1) Css.solid (Css.rgba 255 255 255 0.06)
        , Css.color Style.fg
        , Css.verticalAlign Css.top
        ]


fieldS : Css.Style
fieldS =
    Css.batch [ Css.fontFamilies Style.fontMono, Css.color Style.accent2 ]


typeS : Css.Style
typeS =
    Css.batch [ Css.fontFamilies Style.fontMono, Css.color Style.dim ]


defaultS : Css.Style
defaultS =
    Css.batch [ Css.fontFamilies Style.fontMono, Css.color Style.dim ]


flagS : Css.Style
flagS =
    Css.batch [ Css.fontFamilies Style.fontMono, Css.color Style.fg ]


operandS : Css.Style
operandS =
    Css.batch [ Css.fontFamilies Style.fontMono, Css.color Style.accent2 ]


noneS : Css.Style
noneS =
    Css.batch [ Css.color Style.dim, Css.fontSize (Css.px 11) ]


mutexS : Css.Style
mutexS =
    Css.batch
        [ Css.fontFamilies Style.fontMono
        , Css.fontSize (Css.px 11)
        , Css.color (Css.hex "f0b72f")
        ]


footerS : Css.Style
footerS =
    Css.batch
        [ Css.paddingTop (Css.px 40)
        , Css.paddingBottom (Css.px 60)
        , Css.color Style.dim
        , Css.fontSize (Css.px 12)
        ]
