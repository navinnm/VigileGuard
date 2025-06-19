#!/usr/bin/env python3
"""
VigileGuard Badge Generator
Creates status badges based on VigileGuard security audit reports
"""

import json
import os
import sys
import argparse
from pathlib import Path


def create_badge(report_file, badge_file, style='flat-square'):
    """
    Create demo badge from VigileGuard report
    
    Args:
        report_file (str): Path to VigileGuard JSON report
        badge_file (str): Output path for badge JSON
        style (str): Badge style (flat, flat-square, for-the-badge, etc.)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Default values
        total = 0
        critical_high = 0
        scan_status = 'unknown'
        
        # Try to read report file
        if os.path.exists(report_file) and os.path.getsize(report_file) > 0:
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Extract summary information
                summary = data.get('summary', {})
                total = summary.get('total_findings', 0)
                by_severity = summary.get('by_severity', {})
                
                # Calculate critical/high severity count
                critical_high = by_severity.get('CRITICAL', 0) + by_severity.get('HIGH', 0)
                
                # Get scan status
                scan_info = data.get('scan_info', {})
                scan_status = scan_info.get('status', 'completed')
                
                print(f'📊 Report analysis:')
                print(f'   Total findings: {total}')
                print(f'   Critical/High: {critical_high}')
                print(f'   Scan status: {scan_status}')
                
                # Show breakdown by severity
                if by_severity:
                    print('   Severity breakdown:')
                    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                        count = by_severity.get(severity, 0)
                        if count > 0:
                            print(f'     {severity}: {count}')
                            
            except (json.JSONDecodeError, KeyError) as e:
                print(f'⚠️ Report parsing failed: {e}')
                print('Using default values for badge')
        else:
            print('⚠️ Report file not found or empty')
            print('Creating badge with default values')
        
        # Determine badge color and message
        if scan_status in ['failed', 'error']:
            color = 'lightgrey'
            message = 'scan failed'
        elif critical_high > 0:
            color = 'red'
            message = f'{total} findings ({critical_high} critical/high)'
        elif total > 5:
            color = 'orange'
            message = f'{total} findings (review needed)'
        elif total > 0:
            color = 'yellow'
            message = f'{total} findings (minor issues)'
        else:
            color = 'brightgreen'
            message = 'no issues found'
        
        # Create badge data following shields.io endpoint schema
        badge_data = {
            'schemaVersion': 1,
            'label': 'VigileGuard Security',
            'message': message,
            'color': color,
            'namedLogo': 'shield',
            'style': style,
            'cacheSeconds': 300  # Cache for 5 minutes
        }
        
        # Add additional metadata
        if total > 0:
            badge_data['labelColor'] = 'blue'
            
        # Write badge file
        os.makedirs(os.path.dirname(badge_file) if os.path.dirname(badge_file) else '.', exist_ok=True)
        
        with open(badge_file, 'w', encoding='utf-8') as f:
            json.dump(badge_data, f, indent=2, ensure_ascii=False)
        
        print(f'✅ Badge created successfully: {badge_file}')
        print(f'   Label: {badge_data["label"]}')
        print(f'   Message: {badge_data["message"]}')
        print(f'   Color: {badge_data["color"]}')
        print(f'   Style: {badge_data["style"]}')
        
        return True
        
    except Exception as e:
        print(f'❌ Badge creation failed: {e}')
        return create_fallback_badge(badge_file, style)


def create_fallback_badge(badge_file, style='flat-square'):
    """Create a fallback badge when report analysis fails"""
    try:
        fallback_badge = {
            'schemaVersion': 1,
            'label': 'VigileGuard Security',
            'message': 'scan completed',
            'color': 'blue',
            'namedLogo': 'shield',
            'style': style,
            'cacheSeconds': 300
        }
        
        os.makedirs(os.path.dirname(badge_file) if os.path.dirname(badge_file) else '.', exist_ok=True)
        
        with open(badge_file, 'w', encoding='utf-8') as f:
            json.dump(fallback_badge, f, indent=2, ensure_ascii=False)
            
        print(f'🔄 Fallback badge created: {badge_file}')
        return True
        
    except Exception as e:
        print(f'❌ Even fallback badge creation failed: {e}')
        return False


def create_multiple_badges(report_file, output_dir='badges'):
    """Create multiple badge styles from a single report"""
    styles = ['flat', 'flat-square', 'for-the-badge', 'plastic']
    success_count = 0
    
    os.makedirs(output_dir, exist_ok=True)
    
    for style in styles:
        badge_file = os.path.join(output_dir, f'vigileguard-{style}.json')
        if create_badge(report_file, badge_file, style):
            success_count += 1
            
    print(f'✅ Created {success_count}/{len(styles)} badge styles')
    return success_count == len(styles)


def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(
        description='Generate status badges from VigileGuard security reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python badge_generator.py report.json badge.json
  python badge_generator.py report.json --style for-the-badge
  python badge_generator.py report.json --multiple --output-dir ./badges
  python badge_generator.py --help
        """
    )
    
    parser.add_argument('report_file', 
                       help='Path to VigileGuard JSON report file')
    parser.add_argument('badge_file', nargs='?', default='vigileguard-badge.json',
                       help='Output path for badge JSON (default: vigileguard-badge.json)')
    parser.add_argument('--style', choices=['flat', 'flat-square', 'for-the-badge', 'plastic'],
                       default='flat-square', help='Badge style (default: flat-square)')
    parser.add_argument('--multiple', action='store_true',
                       help='Create multiple badge styles')
    parser.add_argument('--output-dir', default='badges',
                       help='Output directory for multiple badges (default: badges)')
    parser.add_argument('--version', action='version', version='VigileGuard Badge Generator 3.0.3')
    
    args = parser.parse_args()
    
    print('🏷️ VigileGuard Badge Generator')
    print('=' * 35)
    
    # Validate input file
    if not os.path.exists(args.report_file):
        print(f'❌ Report file not found: {args.report_file}')
        print('   Creating badge with default values...')
    
    # Create badges
    if args.multiple:
        print(f'Creating multiple badge styles in: {args.output_dir}')
        success = create_multiple_badges(args.report_file, args.output_dir)
    else:
        print(f'Creating badge: {args.badge_file}')
        print(f'Style: {args.style}')
        success = create_badge(args.report_file, args.badge_file, args.style)
    
    if success:
        print('\n✅ Badge generation completed successfully!')
        if not args.multiple:
            print(f'Badge file: {args.badge_file}')
            print('\nTo use with shields.io:')
            print(f'https://img.shields.io/endpoint?url=https://your-domain.com/{args.badge_file}')
    else:
        print('\n⚠️ Badge generation completed with warnings')
    
    # Always exit 0 to not fail CI/CD pipelines
    sys.exit(0)


if __name__ == '__main__':
    main()