package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "exemorph",
	Short: "ExeMorph is a PE transformation and execution engine",
	Long: `ExeMorph is a CLI tool for analyzing Windows DLLs and converting them 
into standalone executables (EXEs) with intelligent entry point selection 
and robust loader stubs.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do feature or show help
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Global flags can be defined here
}
