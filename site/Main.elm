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
    , route : Route
    , basePath : String
    }


{-| Which page to render. The MFE shell mounts ONE Elm app for every route and
hands it the current `pathname`; the app selects the page from it.
-}
type Route
    = Index
    | Detail Command
    | NotFound String


type Msg
    = NoOp


init : D.Value -> ( Model, Cmd Msg )
init flags =
    case D.decodeValue flagsDecoder flags of
        Ok { pathname, commands } ->
            ( { commands = commands
              , error = Nothing
              , route = routeFor pathname commands
              , basePath = basePathOf pathname
              }
            , Cmd.none
            )

        Err err ->
            ( { commands = [], error = Just (D.errorToString err), route = Index, basePath = "/" }
            , Cmd.none
            )


{-| The site is served under a base path (e.g. `/fx-core`); the sub-path after
it names the command. `''`, `/` and the base itself are the index; anything
else is `/fx-core/<name>`. Unknown names fall through to NotFound.
-}
routeFor : String -> List Command -> Route
routeFor pathname commands =
    case slugOf pathname of
        "" ->
            Index

        slug ->
            case List.filter (\c -> c.name == slug) commands of
                cmd :: _ ->
                    Detail cmd

                [] ->
                    NotFound slug


{-| The site's base path — the first path segment (e.g. `/fx-core`), which is
where the docs are served. Links are built from it so they stay correct whether
the current page is the index (`/fx-core/`) or a command (`/fx-core/ls`).
-}
basePathOf : String -> String
basePathOf pathname =
    case String.split "/" (String.trimRight pathname) |> List.filter (\s -> s /= "") of
        first :: _ ->
            "/" ++ first

        [] ->
            ""


slugOf : String -> String
slugOf pathname =
    let
        trimmed =
            String.split "/" (String.trimRight pathname) |> List.filter (\s -> s /= "")
    in
    case List.reverse trimmed of
        [] ->
            ""

        last :: _ ->
            -- the index page itself ("fx-core") is not a command
            if List.length trimmed == 1 && last == "fx-core" then
                ""

            else
                last


update : Msg -> Model -> ( Model, Cmd Msg )
update _ model =
    ( model, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none


flagsDecoder : D.Decoder { pathname : String, commands : List Command }
flagsDecoder =
    D.map2 (\p c -> { pathname = p, commands = c })
        (D.field "pathname" D.string)
        (D.field "commands" (D.list commandDecoder))


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
                { brand = Styled.a [ href model.basePath, css [ brandLinkS ] ] [ Styled.text "fx-core" ]
                , links =
                    [ Fixpoint.Nav.link "https://fixpointlinux.org" "fixpoint-linux.org"
                    , Fixpoint.Nav.link "https://github.com/fixpoint-linux/fx-core" "github"
                    ]
                , extra = []
                }
            , Styled.main_ [ css [ Style.wrap, mainS ] ]
                [ case model.error of
                    Just err ->
                        Styled.p [ css [ errorS ] ] [ Styled.text ("could not read commands.json: " ++ err) ]

                    Nothing ->
                        case model.route of
                            Index ->
                                indexPage model

                            Detail cmd ->
                                detailPage model cmd

                            NotFound slug ->
                                notFoundPage model slug
                ]
            , footer
            ]


indexPage : Model -> Html msg
indexPage model =
    Styled.div []
        [ header
        , tableOfContents model
        , Styled.div [] (List.map (commandSection model.basePath) model.commands)
        ]


{-| A single-command page: the full argument table plus prev/next navigation
through the (sorted) command list.
-}
detailPage : Model -> Command -> Html msg
detailPage model cmd =
    let
        neighbours =
            neighboursOf cmd.name model.commands
    in
    Styled.div []
        [ Styled.p [ css [ backS ] ]
            [ Styled.a [ href model.basePath ] [ Styled.text "← all commands" ] ]
        , Styled.h1 [ css [ detailTitleS ] ]
            [ Styled.code [ css [ cmdNameS ] ] [ Styled.text ("fx-" ++ cmd.name) ] ]
        , Styled.p [ css [ detailDocS ] ] [ Styled.text cmd.doc ]
        , Styled.p [ css [ usageS ] ] [ Styled.code [] [ Styled.text cmd.usage ] ]
        , if List.isEmpty cmd.args then
            Styled.p [ css [ mutedS ] ] [ Styled.text "No arguments." ]

          else
            argsTable cmd.args
        , mutexNote cmd.mutex
        , prevNext model.basePath neighbours
        ]


type alias Neighbours =
    { prev : Maybe Command, next : Maybe Command }


neighboursOf : String -> List Command -> Neighbours
neighboursOf name commands =
    case indexOfName name commands 0 of
        Nothing ->
            { prev = Nothing, next = Nothing }

        Just i ->
            { prev = nth (i - 1) commands
            , next = nth (i + 1) commands
            }


indexOfName : String -> List Command -> Int -> Maybe Int
indexOfName name commands i =
    case commands of
        [] ->
            Nothing

        c :: rest ->
            if c.name == name then
                Just i

            else
                indexOfName name rest (i + 1)


nth : Int -> List Command -> Maybe Command
nth i commands =
    if i < 0 then
        Nothing

    else
        List.head (List.drop i commands)


prevNext : String -> Neighbours -> Html msg
prevNext basePath n =
    Styled.nav [ css [ pagerS ] ]
        [ case n.prev of
            Just c ->
                Styled.a [ href (basePath ++ "/" ++ c.name), css [ pagerLinkS ] ]
                    [ Styled.text ("← fx-" ++ c.name) ]

            Nothing ->
                Styled.span [] []
        , case n.next of
            Just c ->
                Styled.a [ href (basePath ++ "/" ++ c.name), css [ pagerLinkS, pagerNextS ] ]
                    [ Styled.text ("fx-" ++ c.name ++ " →") ]

            Nothing ->
                Styled.span [] []
        ]


notFoundPage : Model -> String -> Html msg
notFoundPage model slug =
    Styled.div []
        [ Styled.h1 [] [ Styled.text "Not found" ]
        , Styled.p []
            [ Styled.text ("No command named "), Styled.code [] [ Styled.text slug ], Styled.text "." ]
        , Styled.p []
            [ Styled.a [ href model.basePath ] [ Styled.text "← all commands" ] ]
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


{-| A compact index of every command, so a reader can jump (anchors are the
command names, set on each section).
-}
tableOfContents : Model -> Html msg
tableOfContents model =
    Styled.nav [ css [ tocS ] ]
        (Styled.span [ css [ tocHeadS ] ] [ Styled.text "Commands" ]
            :: List.map
                (\c -> Styled.a [ href (model.basePath ++ "/" ++ c.name), css [ tocLinkS ] ]
                    [ Styled.text c.name ]
                )
                model.commands
        )


commandSection : String -> Command -> Html msg
commandSection basePath cmd =
    Styled.section [ css [ cmdS ], Attr.id cmd.name ]
        [ Styled.h2 [ css [ cmdHeadS ] ]
            [ Styled.a [ href (basePath ++ "/" ++ cmd.name), css [ cmdLinkS ] ]
                [ Styled.code [ css [ cmdNameS ] ] [ Styled.text ("fx-" ++ cmd.name) ] ]
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
        , Styled.td [ css [ tdS, defaultS ] ] [ Styled.code [] [ Styled.text (displayDefault arg.default) ] ]
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
                    Styled.span [ css [ noneS ] ] [ Styled.text "—" ]

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


{-| The default, as a reader wants to see it. The Dhall source spells an empty
list `[] : List Text` and an absent optional `None Text`; the type column
already carries the type, so strip the annotation here.
-}
displayDefault : String -> String
displayDefault d =
    if String.startsWith "[] :" d then
        "[]"

    else if String.startsWith "None " d then
        "None"

    else
        d


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


tocS : Css.Style
tocS =
    Css.batch
        [ Css.displayFlex
        , Css.flexWrap Css.wrap
        , Css.property "gap" "6px 14px"
        , Css.padding3 (Css.px 16) (Css.px 18) (Css.px 16)
        , Css.border3 (Css.px 1) Css.solid Style.line
        , Css.borderRadius (Css.px 8)
        , Css.backgroundColor Style.bg2
        , Css.marginBottom (Css.px 24)
        , Css.fontSize (Css.px 12)
        ]


tocHeadS : Css.Style
tocHeadS =
    Css.batch
        [ Css.fontFamilies Style.fontMono
        , Css.color Style.dim
        , Css.width (Css.pct 100)
        , Css.marginBottom (Css.px 4)
        , Css.fontSize (Css.px 11)
        ]


tocLinkS : Css.Style
tocLinkS =
    Css.batch [ Css.fontFamilies Style.fontMono, Css.color Style.accent2 ]


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


brandLinkS : Css.Style
brandLinkS =
    Css.batch [ Css.color Style.fg, Css.hover [ Css.textDecoration Css.none, Css.color Style.accent ] ]


cmdLinkS : Css.Style
cmdLinkS =
    Css.batch [ Css.hover [ Css.textDecoration Css.none ] ]


backS : Css.Style
backS =
    Css.batch [ Css.fontSize (Css.px 13), Css.marginBottom (Css.px 18) ]


detailTitleS : Css.Style
detailTitleS =
    Css.batch [ Css.marginBottom (Css.px 6) ]


detailDocS : Css.Style
detailDocS =
    Css.batch [ Css.color Style.fg, Css.fontSize (Css.px 15), Css.marginBottom (Css.px 10) ]


pagerS : Css.Style
pagerS =
    Css.batch
        [ Css.displayFlex
        , Css.justifyContent Css.spaceBetween
        , Css.marginTop (Css.px 24)
        , Css.paddingTop (Css.px 14)
        , Css.borderTop3 (Css.px 1) Css.solid Style.line
        , Css.fontFamilies Style.fontMono
        , Css.fontSize (Css.px 13)
        ]


pagerLinkS : Css.Style
pagerLinkS =
    Css.batch [ Css.color Style.accent2 ]


pagerNextS : Css.Style
pagerNextS =
    Css.batch [ Css.marginLeft Css.auto ]


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
