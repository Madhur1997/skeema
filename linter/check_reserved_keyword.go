package linter

import (
	"fmt"
	"regexp"

	"github.com/skeema/tengo"
)

// Percona's keyword list is same as mysql.
var mysqlKeywordToFlavor = map[string]tengo.Flavor{
	"GET" : tengo.FlavorMySQL56,
	"IO_AFTER_GTIDS": tengo.FlavorMySQL56,
	"IO_BEFORE_GTIDS": tengo.FlavorMySQL56,
	"MASTER_BIND": tengo.FlavorMySQL56,
	"GENERATED": tengo.FlavorMySQL57,
	"OPTIMIZER_COSTS": tengo.FlavorMySQL57,
	"STORED": tengo.FlavorMySQL57,
	"VIRTUAL": tengo.FlavorMySQL57,
	"CUME_DIST": tengo.FlavorMySQL80,
	"DENSE_RANK": tengo.FlavorMySQL80,
	"EMPTY": tengo.FlavorMySQL80,
	"EXCEPT": tengo.FlavorMySQL80,
	"FIRST_VALUE": tengo.FlavorMySQL80,
	"GROUPING": tengo.FlavorMySQL80,
	"GROUPS": tengo.FlavorMySQL80,
	"JSON_TABLE": tengo.FlavorMySQL80,
	"LAG": tengo.FlavorMySQL80,
	"LAST_VALUE": tengo.FlavorMySQL80,
	"LATERAL": tengo.FlavorMySQL80,
	"LEAD": tengo.FlavorMySQL80,
	"NTH_VALUE": tengo.FlavorMySQL80,
	"NTILE": tengo.FlavorMySQL80,
	"OF": tengo.FlavorMySQL80,
	"OVER": tengo.FlavorMySQL80,
	"PERCENT_RANK": tengo.FlavorMySQL80,
	"RANK": tengo.FlavorMySQL80,
	"RECURSIVE": tengo.FlavorMySQL80,
	"ROW_NUMBER": tengo.FlavorMySQL80,
	"SYSTEM": tengo.FlavorMySQL80,
	"WINDOW": tengo.FlavorMySQL80,
}

var mariadbKeywordToFlavor = map[string]tengo.Flavor{
	"DO_DOMAIN_IDS": tengo.FlavorMariaDB101,
	"IGNORE_DOMAIN_IDS": tengo.FlavorMariaDB101,
	"REF_SYSTEM_ID": tengo.FlavorMariaDB101,
	"OVER": tengo.FlavorMariaDB102,
	"RECURSIVE": tengo.FlavorMariaDB102,
	"ROWS": tengo.FlavorMariaDB102,
	"WINDOW": tengo.FlavorMariaDB102,
	"EXCEPT": tengo.FlavorMariaDB103,
	"INTERSECT": tengo.FlavorMariaDB103,
}


func init() {
	RegisterRule(Rule{
		CheckerFunc:     CommonChecker(reservedWordsChecker),
		Name:            "reserved-words",
		Description:     "Flag identifiers being used as reserved words",
		DefaultSeverity: SeverityWarning,
	})
}

func generateMessage(field string, fieldName string, table string, flavorString string) (message string) {
		message = fmt.Sprintf(
			"%s %s of %s table is using a name which is a reserved keyword in %s and above. Consider renaming the %s to a non reserved word or enclose it with double quotes for compatibility with future upgrades.",
			field, fieldName, table, flavorString, field )
		return
}

func tableReservedWordsChecker(table *tengo.Table, createStatement string, keywordToFlavor map[string]tengo.Flavor) []Note {

	results := make([]Note, 0)

	if flavor, found := keywordToFlavor[table.Name]; found {
		re := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(table.Name)))
		message := fmt.Sprintf(
			"Table %s is using a name which is a reserved keyword in %s and above. Consider renaming the Table to a non reserved word or enclose it with double quotes for compatibility with future upgrades.",
			table.Name, flavor.String() )
		results = append(results, Note{
			LineOffset: FindFirstLineOffset(re, createStatement),
			Summary:    "Table using a reserved keyword",
			Message:    message,
		})
	}

	for _, col := range table.Columns {
		if flavor, found := keywordToFlavor[col.Name]; found {
			re := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(col.Name)))
			message := generateMessage( "Column", col.Name, table.Name, flavor.String() )
			results = append(results, Note{
				LineOffset: FindFirstLineOffset(re, createStatement),
				Summary:    "Column using a reserved keyword",
				Message:    message,
			})
		}
	}

	for _, fk := range table.ForeignKeys {
		if flavor, found := keywordToFlavor[fk.Name]; found {
			re := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(fk.Name)))
			message := generateMessage( "Foreign Key", fk.Name, table.Name, flavor.String() )
			results = append(results, Note{
				LineOffset: FindFirstLineOffset(re, createStatement),
				Summary:    "Foreign Key using a reserved keyword",
				Message:    message,
			})
		}
	}

	for _, idx := range table.SecondaryIndexes {
		if flavor, found := keywordToFlavor[idx.Name]; found {
			re := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(idx.Name)))
			message := generateMessage( "Index", idx.Name, table.Name, flavor.String() )
			results = append(results, Note{
				LineOffset: FindFirstLineOffset(re, createStatement),
				Summary:    "Index using a reserved keyword",
				Message:    message,
				})
		}
	}
	return results
}

func routineReservedWordsChecker(routine *tengo.Routine, createStatement string, keywordToFlavor map[string]tengo.Flavor) []Note {
	results := make([]Note, 0)
	if flavor, found := keywordToFlavor[routine.Name]; found {
		re := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(routine.Name)))
		message := fmt.Sprintf(
			"Routine %s is using a name which is a reserved keyword in %s and above. Consider renaming the Routine to a non reserved word or enclose it with double quotes for compatibility with future upgrades.", routine.Name, flavor.String() )
		results = append(results, Note{
			LineOffset: FindFirstLineOffset(re, createStatement),
			Summary:    "Routine using a reserved keyword",
			Message:    message,
		})
	}
	return results
}

func reservedWordsChecker(object interface{}, createStatement string, _ *tengo.Schema, opts Options) []Note {

	var keywordToFlavor map[string]tengo.Flavor
	if opts.Flavor.Vendor == tengo.VendorMySQL || opts.Flavor.Vendor == tengo.VendorPercona {
		keywordToFlavor = mysqlKeywordToFlavor
	} else if opts.Flavor.Vendor == tengo.VendorMariaDB {
		keywordToFlavor = mariadbKeywordToFlavor
	} else {
		return []Note{}
	}

	if table, ok := object.(*tengo.Table); ok {
		return tableReservedWordsChecker(table, createStatement, keywordToFlavor)
	} else if routine, ok := object.(*tengo.Routine); ok {
		return routineReservedWordsChecker(routine, createStatement, keywordToFlavor)
	} else {
		return []Note{}
	}
}
