#!/usr/bin/env python3
"""
HashID-Pro - CLI Entry Point
A powerful hash identification tool with support for multiple hash types.
"""

import argparse
import sys

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    print("Error: The 'rich' library is required. Install it with: pip install rich")
    sys.exit(1)

from analyzer import HashAnalyzer


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser for the CLI.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='hashid-pro',
        description='Identify hash types from hash strings. Supports MD5, SHA-1, SHA-256, SHA-512, Bcrypt, NTLM, MySQL5, and more.',
        epilog='Example: python main.py 5d41402abc4b2a76b9719d911017c592'
    )
    
    parser.add_argument(
        'hash',
        type=str,
        help='The hash string to identify'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    return parser


def display_results(hash_string: str, results: list, console: Console) -> None:
    """
    Display analysis results in a formatted table using rich.
    
    Args:
        hash_string: The original hash string analyzed
        results: List of possible hash type matches
        console: Rich Console instance for output
    """
    # Create header panel
    header_text = Text()
    header_text.append("HashID-Pro", style="bold cyan")
    header_text.append(" - Hash Identification Tool", style="dim")
    console.print(Panel(header_text, border_style="cyan"))
    
    # Display the input hash
    console.print(f"\n[bold white]Input Hash:[/bold white] [yellow]{hash_string}[/yellow]")
    console.print(f"[bold white]Length:[/bold white] [yellow]{len(hash_string)}[/yellow] characters\n")
    
    if not results:
        console.print("[bold red]No matching hash types found.[/bold red]")
        console.print("[dim]The provided string does not match any known hash pattern.[/dim]")
        return
    
    # Create results table
    table = Table(
        title="Possible Hash Types",
        show_header=True,
        header_style="bold magenta",
        border_style="blue"
    )
    
    table.add_column("Algorithm", style="cyan", justify="left", min_width=15)
    table.add_column("Confidence/Note", style="white", justify="left", min_width=40)
    
    for result in results:
        # Format confidence level with color
        confidence = result['confidence'].upper()
        if confidence == 'HIGH':
            confidence_text = f"[bold green]{confidence}[/bold green]"
        elif confidence == 'MEDIUM':
            confidence_text = f"[bold yellow]{confidence}[/bold yellow]"
        else:
            confidence_text = f"[bold red]{confidence}[/bold red]"
        
        # Build the note column content
        note_parts = [f"Confidence: {confidence_text}"]
        note_parts.append(f"[dim]{result['description']}[/dim]")
        
        if result['note']:
            note_parts.append(f"[italic yellow]Note: {result['note']}[/italic yellow]")
        
        note_column = "\n".join(note_parts)
        
        table.add_row(result['type'], note_column)
    
    console.print(table)
    
    # Summary
    console.print(f"\n[bold green]Found {len(results)} possible match(es).[/bold green]")


def main() -> int:
    """
    Main entry point for the CLI application.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    console = Console()
    
    # Parse arguments
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate input - check for empty string
    hash_string = args.hash.strip()
    
    if not hash_string:
        console.print("[bold red]Error:[/bold red] Empty hash string provided.")
        console.print("[dim]Please provide a valid hash string to analyze.[/dim]")
        console.print("\n[bold]Usage:[/bold] python main.py <hash_string>")
        console.print("[bold]Example:[/bold] python main.py 5d41402abc4b2a76b9719d911017c592")
        return 1
    
    try:
        # Create analyzer and analyze the hash
        analyzer = HashAnalyzer()
        results = analyzer.analyze(hash_string)
        
        # Display results
        display_results(hash_string, results, console)
        
        return 0
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] An unexpected error occurred: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
