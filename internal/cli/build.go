package cli

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/ExeMorph/internal/transform"
	"github.com/spf13/cobra"
)

var (
	entryExport string
	outputFile  string
)

var buildCmd = &cobra.Command{
	Use:   "build [dll_file]",
	Short: "Convert a DLL to an EXE",
	Long: `Build transforms the target DLL into a standalone Executable.
It removes the DLL characteristics, injects a boostrap loader, and
redirects the entry point to the selected export.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dllPath := args[0]

		if outputFile == "" {
			outputFile = dllPath + ".exe"
		}

		fmt.Printf("Building EXE from %s...\n", dllPath)
		fmt.Printf(" - Target Export: %s\n", entryExport)
		fmt.Printf(" - Output File: %s\n", outputFile)

		opts := transform.BuildOptions{
			EntryExport: entryExport,
			OutputFile:  outputFile,
		}

		if err := transform.Transform(dllPath, opts); err != nil {
			fmt.Fprintf(os.Stderr, "Build failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	buildCmd.Flags().StringVar(&entryExport, "entry", "", "Name of the exported function to execute (optional)")
	buildCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output EXE path")

	rootCmd.AddCommand(buildCmd)
}
