package cli

import (
	"fmt"
	"os"

	"github.com/ismailtsdln/ExeMorph/internal/analysis"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [file]",
	Short: "Analyze a DLL file for execution candidates",
	Long: `Analyze inspects the PE structure of a DLL, finding exported functions,
entry points (DllMain), and architectural details. It provides a scoring
mechanism to suggest the best entry point for conversion.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		peFile, err := analysis.NewPEFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer peFile.Close()

		fmt.Printf("Analyzing %s...\n", filePath)
		fmt.Printf("Architecture: %s\n", peFile.GetArch())
		fmt.Printf("Is DLL: %v\n", peFile.IsDLL())

		scanner := analysis.NewScanner(peFile)
		candidates, err := scanner.ScanCandidates()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning file: %v\n", err)
			os.Exit(1)
		}

		// Quick output for CLI
		fmt.Println("\nExecution Candidates:")
		for _, c := range candidates {
			fmt.Printf(" - [%s] %s (Addr: 0x%X, Score: %.2f)\n", c.Type, c.Name, c.Address, c.Confidence)
		}

		// If debug or JSON flag is set, we might output more details
		// For now simple plain text
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
