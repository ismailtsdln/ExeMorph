package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
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
			color.Red("Error opening file: %v", err)
			os.Exit(1)
		}
		defer peFile.Close()

		header := color.New(color.FgCyan, color.Bold)
		header.Printf("Analyzing %s...\n", filePath)

		fmt.Printf("Architecture: %s\n", color.YellowString(peFile.GetArch()))
		fmt.Printf("Is DLL: %v\n", color.BlueString("%v", peFile.IsDLL()))

		scanner := analysis.NewScanner(peFile)
		candidates, err := scanner.ScanCandidates()
		if err != nil {
			color.Red("Error scanning file: %v", err)
			os.Exit(1)
		}

		fmt.Println()
		header.Println("Execution Candidates:")

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "TYPE\tNAME\tADDRESS\tSCORE")

		for _, c := range candidates {
			scoreColor := color.FgRed
			if c.Confidence >= 0.9 {
				scoreColor = color.FgGreen
			} else if c.Confidence >= 0.5 {
				scoreColor = color.FgYellow
			}

			scoreStr := color.New(scoreColor).Sprintf("%.2f", c.Confidence)
			fmt.Fprintf(w, "%s\t%s\t0x%X\t%s\n", c.Type, c.Name, c.Address, scoreStr)
		}
		w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
