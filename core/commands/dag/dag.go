package dagcmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/ipfs/go-ipfs/core/commands/cmdenv"
	"github.com/ipfs/go-ipfs/core/coredag"

	cid "github.com/ipfs/go-cid"
	cidenc "github.com/ipfs/go-cidutil/cidenc"
	cmds "github.com/ipfs/go-ipfs-cmds"
	files "github.com/ipfs/go-ipfs-files"
	ipld "github.com/ipfs/go-ipld-format"
	mdag "github.com/ipfs/go-merkledag"
	ipfspath "github.com/ipfs/go-path"
	path "github.com/ipfs/interface-go-ipfs-core/path"
	mh "github.com/multiformats/go-multihash"

	gocar "github.com/ipld/go-car"
	gipfree "github.com/ipld/go-ipld-prime/impl/free"
	gipselector "github.com/ipld/go-ipld-prime/traversal/selector"
	gipselectorbuilder "github.com/ipld/go-ipld-prime/traversal/selector/builder"
)

var DagCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Interact with ipld dag objects.",
		ShortDescription: `
'ipfs dag' is used for creating and manipulating dag objects.

This subcommand is currently an experimental feature, but it is intended
to deprecate and replace the existing 'ipfs object' command moving forward.
		`,
	},
	Subcommands: map[string]*cmds.Command{
		"put":     DagPutCmd,
		"get":     DagGetCmd,
		"resolve": DagResolveCmd,
		"export":  DagExportCmd,
	},
}

// OutputObject is the output type of 'dag put' command
type OutputObject struct {
	Cid cid.Cid
}

// ResolveOutput is the output type of 'dag resolve' command
type ResolveOutput struct {
	Cid     cid.Cid
	RemPath string
}

var DagPutCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Add a dag node to ipfs.",
		ShortDescription: `
'ipfs dag put' accepts input from a file or stdin and parses it
into an object of the specified format.
`,
	},
	Arguments: []cmds.Argument{
		cmds.FileArg("object data", true, true, "The object to put").EnableStdin(),
	},
	Options: []cmds.Option{
		cmds.StringOption("format", "f", "Format that the object will be added as.").WithDefault("cbor"),
		cmds.StringOption("input-enc", "Format that the input object will be.").WithDefault("json"),
		cmds.BoolOption("pin", "Pin this object when adding."),
		cmds.StringOption("hash", "Hash function to use").WithDefault(""),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		ienc, _ := req.Options["input-enc"].(string)
		format, _ := req.Options["format"].(string)
		hash, _ := req.Options["hash"].(string)
		dopin, _ := req.Options["pin"].(bool)

		// mhType tells inputParser which hash should be used. MaxUint64 means 'use
		// default hash' (sha256 for cbor, sha1 for git..)
		mhType := uint64(math.MaxUint64)

		if hash != "" {
			var ok bool
			mhType, ok = mh.Names[hash]
			if !ok {
				return fmt.Errorf("%s in not a valid multihash name", hash)
			}
		}

		var adder ipld.NodeAdder = api.Dag()
		if dopin {
			adder = api.Dag().Pinning()
		}
		b := ipld.NewBatch(req.Context, adder)

		it := req.Files.Entries()
		for it.Next() {
			file := files.FileFromEntry(it)
			if file == nil {
				return fmt.Errorf("expected a regular file")
			}
			nds, err := coredag.ParseInputs(ienc, format, file, mhType, -1)
			if err != nil {
				return err
			}
			if len(nds) == 0 {
				return fmt.Errorf("no node returned from ParseInputs")
			}

			for _, nd := range nds {
				err := b.Add(req.Context, nd)
				if err != nil {
					return err
				}
			}

			cid := nds[0].Cid()
			if err := res.Emit(&OutputObject{Cid: cid}); err != nil {
				return err
			}
		}
		if it.Err() != nil {
			return it.Err()
		}

		if err := b.Commit(); err != nil {
			return err
		}

		return nil
	},
	Type: OutputObject{},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, out *OutputObject) error {
			enc, err := cmdenv.GetLowLevelCidEncoder(req)
			if err != nil {
				return err
			}
			fmt.Fprintln(w, enc.Encode(out.Cid))
			return nil
		}),
	},
}

var DagGetCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Get a dag node from ipfs.",
		ShortDescription: `
'ipfs dag get' fetches a dag node from ipfs and prints it out in the specified
format.
`,
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("ref", true, false, "The object to get").EnableStdin(),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		rp, err := api.ResolvePath(req.Context, path.New(req.Arguments[0]))
		if err != nil {
			return err
		}

		obj, err := api.Dag().Get(req.Context, rp.Cid())
		if err != nil {
			return err
		}

		var out interface{} = obj
		if len(rp.Remainder()) > 0 {
			rem := strings.Split(rp.Remainder(), "/")
			final, _, err := obj.Resolve(rem)
			if err != nil {
				return err
			}
			out = final
		}
		return cmds.EmitOnce(res, &out)
	},
}

// DagResolveCmd returns address of highest block within a path and a path remainder
var DagResolveCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		Tagline: "Resolve ipld block",
		ShortDescription: `
'ipfs dag resolve' fetches a dag node from ipfs, prints it's address and remaining path.
`,
	},
	Arguments: []cmds.Argument{
		cmds.StringArg("ref", true, false, "The path to resolve").EnableStdin(),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		rp, err := api.ResolvePath(req.Context, path.New(req.Arguments[0]))
		if err != nil {
			return err
		}

		return cmds.EmitOnce(res, &ResolveOutput{
			Cid:     rp.Cid(),
			RemPath: rp.Remainder(),
		})
	},
	Encoders: cmds.EncoderMap{
		cmds.Text: cmds.MakeTypedEncoder(func(req *cmds.Request, w io.Writer, out *ResolveOutput) error {
			var (
				enc cidenc.Encoder
				err error
			)
			switch {
			case !cmdenv.CidBaseDefined(req):
				// Not specified, check the path.
				enc, err = cmdenv.CidEncoderFromPath(req.Arguments[0])
				if err == nil {
					break
				}
				// Nope, fallback on the default.
				fallthrough
			default:
				enc, err = cmdenv.GetLowLevelCidEncoder(req)
				if err != nil {
					return err
				}
			}
			p := enc.Encode(out.Cid)
			if out.RemPath != "" {
				p = ipfspath.Join([]string{p, out.RemPath})
			}

			fmt.Fprint(w, p)
			return nil
		}),
	},
	Type: ResolveOutput{},
}

var DagExportCmd = &cmds.Command{
	Helptext: cmds.HelpText{
		// Q: Is this a correct description? do we stream "on stdout" or do we say something else?
		Tagline: "Streams the selected DAG as a .car stream on stdout.",
		ShortDescription: `
'ipfs dag export' fetches a dag and streams it out as a well-formed .car file.
`,
	},
	Arguments: []cmds.Argument{
		// Q: Is this the right way to pull in a CID from both arg and STDIN?
		// Q: Is the "variadic false" the right way to say "just one right now"
		// Q: Is this sufficiently "future proof" for plugging proper at the same spot?
		cmds.StringArg("ref", true, false, "The root CID of the dag to export").EnableStdin(),
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) error {
		node, err := cmdenv.GetNode(env)
		if err != nil {
			return err
		}

		api, err := cmdenv.GetApi(env, req)
		if err != nil {
			return err
		}

		rp, err := api.ResolvePath(req.Context, path.New(req.Arguments[0]))
		if err != nil {
			return err
		}

		sb := gipselectorbuilder.NewSelectorSpecBuilder(gipfree.NodeBuilder())

		car := gocar.NewSelectiveCar(
			req.Context,
			node.Blockstore,
			[]gocar.Dag{gocar.Dag{
				Root:     rp.Cid(),
				Selector: sb.ExploreRecursive(gipselector.RecursionLimitNone(), sb.ExploreAll(sb.ExploreRecursiveEdge())).Node(),
			}},
		)

		// Lock the blockstore so blocks do not disappear on us while exporting
		unlocker := node.Blockstore.GCLock()
		if unlocker == nil {
			return errors.New("unable to obtain GC lock")
		}
		// Q: Is it correct to ignore the Unlock error - is there something I can do with it?
		defer func() { unlocker.Unlock() }()

		// Q: is this really the best we can do?
		//
		// Force a full graph fetch before exporting
		// Extraordinarely inefficient ( no chance for streaming )
		// but NewSelectiveCar only takes a blockstore...
		//
		// Q: how can I properly determine if I am online, and augment the error:
		// instead of saying `Error: merkledag: not found`
		// to do something like `Error: merkledag: not found ( node is currently offline )`
		if err := mdag.FetchGraph(req.Context, rp.Cid(), node.DAG); err != nil {
			return err
		}

		// Q: I wrote this *before* you answered about io.pipe
		// Is there anything to gain by switching to io.pipe ( and paying for an extra goroutine )
		// or is this an acceptable/idiomatic way to stream out?
		// ( the Emit()ter seems async already )
		var cbwriter writeCallback = func(p []byte) (int, error) {
			if err := res.Emit(bytes.NewReader(p)); err != nil {
				return 0, err
			}
			return len(p), nil
		}

		return car.Write(&cbwriter)
	},
}

type writeCallback func([]byte) (int, error)

func (c *writeCallback) Write(p []byte) (int, error) {
	return (*c)(p)
}
